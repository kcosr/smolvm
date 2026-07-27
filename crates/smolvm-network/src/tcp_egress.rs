//! Configurable TCP egress routing for the virtio-net gateway.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, BufReader, Cursor, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::Resumption;
use rustls::pki_types::ServerName;
use rustls::{
    ClientConfig, ClientConnection, HandshakeKind, ProtocolVersion, RootCertStore, StreamOwned,
};
use zeroize::Zeroizing;

/// Host environment variable containing the AWAF bearer directly.
pub const AWAF_BEARER_ENV: &str = "SMOLVM_AWAF_BEARER";
/// Host environment variable containing a path from which to read the AWAF bearer.
pub const AWAF_BEARER_FILE_ENV: &str = "SMOLVM_AWAF_BEARER_FILE";

const ACCESS_FLOW_HEADER_LEN: usize = 16;
const MIN_BEARER_LEN: usize = 32;
const MAX_BEARER_LEN: usize = 4096;
const ACCESS_FLOW_SETUP_TIMEOUT: Duration = Duration::from_secs(5);
const ACCESS_FLOW_TLS_ALPN: &[u8] = b"aw-access-flow/1";
const MAX_TRUST_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TRUST_CERTIFICATES: usize = 128;
const MAX_TRUST_CERTIFICATE_BYTES: usize = 64 * 1024;

type TlsStream = StreamOwned<ClientConnection, TcpStream>;

/// Default handling for TCP destination ports absent from explicit route lists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmatchedTcp {
    /// Open a normal host TCP connection.
    #[default]
    Direct,
    /// Reject the guest TCP flow before creating a host socket.
    Deny,
}

impl FromStr for UnmatchedTcp {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct" => Ok(Self::Direct),
            "deny" => Ok(Self::Deny),
            _ => Err("expected 'direct' or 'deny'"),
        }
    }
}

/// Host connector for one AWAF-routed destination port.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccessFlowEndpoint {
    /// Connect to a host Unix-domain socket.
    Unix { path: PathBuf },
    /// Connect using server-authenticated TLS 1.3 over TCP.
    TlsTcp {
        address: String,
        server_name: String,
        trust_path: PathBuf,
    },
}

impl AccessFlowEndpoint {
    /// Construct a Unix endpoint.
    pub fn unix(path: PathBuf) -> io::Result<Self> {
        let endpoint = Self::Unix { path };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Construct a TLS/TCP endpoint.
    pub fn tls_tcp(address: String, server_name: String, trust_path: PathBuf) -> io::Result<Self> {
        let endpoint = Self::TlsTcp {
            address,
            server_name,
            trust_path,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    /// Validate persisted endpoint fields without opening the endpoint.
    pub fn validate(&self) -> io::Result<()> {
        match self {
            Self::Unix { path } => {
                validate_socket_path(path)?;
                #[cfg(not(unix))]
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "AWAF Unix socket egress is unsupported on this host; use tls://",
                ));
                #[cfg(unix)]
                Ok(())
            }
            Self::TlsTcp {
                address,
                server_name,
                trust_path,
            } => {
                validate_tls_address(address)?;
                validate_server_name(server_name)?;
                validate_trust_path(trust_path)
            }
        }
    }

    /// Unix socket path requiring host read/write access.
    pub fn unix_socket_path(&self) -> Option<&Path> {
        match self {
            Self::Unix { path } => Some(path),
            Self::TlsTcp { .. } => None,
        }
    }

    /// PEM trust bundle requiring host read access.
    pub fn tls_trust_path(&self) -> Option<&Path> {
        match self {
            Self::Unix { .. } => None,
            Self::TlsTcp { trust_path, .. } => Some(trust_path),
        }
    }

    const fn requires_bearer(&self) -> bool {
        matches!(self, Self::TlsTcp { .. })
    }
}

/// Persisted per-VM TCP routing configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpEgressConfig {
    access_flow_routes: BTreeMap<u16, AccessFlowEndpoint>,
    direct_ports: BTreeSet<u16>,
    #[serde(default)]
    unmatched: UnmatchedTcp,
}

impl TcpEgressConfig {
    /// Validate and construct one TCP routing configuration.
    pub fn new(
        access_flow_routes: BTreeMap<u16, AccessFlowEndpoint>,
        direct_ports: BTreeSet<u16>,
        unmatched: UnmatchedTcp,
    ) -> io::Result<Self> {
        let config = Self {
            access_flow_routes,
            direct_ports,
            unmatched,
        };
        config.validate()?;
        Ok(config)
    }

    /// Validate a deserialized TCP routing configuration.
    pub fn validate(&self) -> io::Result<()> {
        for (&port, endpoint) in &self.access_flow_routes {
            validate_port(port, "AWAF route")?;
            endpoint.validate()?;
            if self.direct_ports.contains(&port) {
                return Err(invalid_config(format!(
                    "TCP destination port {port} has both AWAF and direct routes"
                )));
            }
        }
        for &port in &self.direct_ports {
            validate_port(port, "direct TCP route")?;
        }
        Ok(())
    }

    /// AWAF destination-port to host connector mappings.
    pub fn access_flow_routes(&self) -> &BTreeMap<u16, AccessFlowEndpoint> {
        &self.access_flow_routes
    }

    /// Destination ports that retain direct host TCP connections.
    pub fn direct_ports(&self) -> &BTreeSet<u16> {
        &self.direct_ports
    }

    /// Handling for destination ports absent from both explicit route sets.
    pub const fn unmatched(&self) -> UnmatchedTcp {
        self.unmatched
    }
}

/// One validated AWAF upstream shared by every flow for its destination port.
pub struct AccessFlowProxy {
    endpoint: PreparedAccessFlowEndpoint,
    bearer: Option<Arc<Zeroizing<Vec<u8>>>>,
}

enum PreparedAccessFlowEndpoint {
    #[cfg(unix)]
    Unix(PathBuf),
    TlsTcp {
        addresses: Vec<SocketAddr>,
        server_name: ServerName<'static>,
        client_config: Arc<ClientConfig>,
    },
}

impl fmt::Debug for AccessFlowProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let transport = match &self.endpoint {
            #[cfg(unix)]
            PreparedAccessFlowEndpoint::Unix(_) => "unix",
            PreparedAccessFlowEndpoint::TlsTcp { .. } => "tls_tcp",
        };
        formatter
            .debug_struct("AccessFlowProxy")
            .field("transport", &transport)
            .field("authenticated", &self.bearer.is_some())
            .finish()
    }
}

impl AccessFlowProxy {
    pub(crate) fn connect(&self, destination: SocketAddr) -> io::Result<AccessFlowStream> {
        let preface = encode_preface(
            destination,
            self.bearer.as_ref().map(|bearer| bearer.as_slice()),
        )?;
        let stream = match &self.endpoint {
            #[cfg(unix)]
            PreparedAccessFlowEndpoint::Unix(path) => {
                let stream = UnixStream::connect(path)?;
                stream.set_write_timeout(Some(ACCESS_FLOW_SETUP_TIMEOUT))?;
                let mut stream = AccessFlowStream::Unix(stream);
                stream.write_all(preface.as_slice())?;
                stream.flush()?;
                stream
            }
            PreparedAccessFlowEndpoint::TlsTcp {
                addresses,
                server_name,
                client_config,
            } => AccessFlowStream::Tls(Box::new(connect_tls(
                addresses,
                server_name.clone(),
                Arc::clone(client_config),
                preface.as_slice(),
            )?)),
        };
        stream.clear_setup_timeouts()?;
        Ok(stream)
    }

    #[cfg(test)]
    pub(crate) fn tls_for_test(
        address: SocketAddr,
        server_name: ServerName<'static>,
        client_config: Arc<ClientConfig>,
        bearer: Vec<u8>,
    ) -> Arc<Self> {
        Arc::new(Self {
            endpoint: PreparedAccessFlowEndpoint::TlsTcp {
                addresses: vec![address],
                server_name,
                client_config,
            },
            bearer: Some(Arc::new(Zeroizing::new(bearer))),
        })
    }
}

/// Established host-side AWAF stream.
pub(crate) enum AccessFlowStream {
    #[cfg(unix)]
    Unix(UnixStream),
    Tls(Box<TlsStream>),
}

impl AccessFlowStream {
    pub(crate) fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_nonblocking(nonblocking),
            Self::Tls(stream) => stream.sock.set_nonblocking(nonblocking),
        }
    }

    pub(crate) fn shutdown(&mut self, how: Shutdown) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(how),
            Self::Tls(stream) => {
                if matches!(how, Shutdown::Write | Shutdown::Both) {
                    stream.conn.send_close_notify();
                    stream.flush()?;
                }
                stream.sock.shutdown(how)
            }
        }
    }

    fn clear_setup_timeouts(&self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => {
                stream.set_read_timeout(None)?;
                stream.set_write_timeout(None)
            }
            Self::Tls(stream) => {
                stream.sock.set_read_timeout(None)?;
                stream.sock.set_write_timeout(None)
            }
        }
    }
}

impl Read for AccessFlowStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for AccessFlowStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

/// Routing decision for one guest-initiated TCP flow.
pub(crate) enum TcpRoute {
    Direct,
    AccessFlow(Arc<AccessFlowProxy>),
    Deny,
}

/// Runtime routing policy with bearer material resolved for this VM launch.
#[derive(Clone, Debug)]
pub(crate) struct TcpEgressPolicy {
    access_flow_routes: BTreeMap<u16, Arc<AccessFlowProxy>>,
    direct_ports: BTreeSet<u16>,
    unmatched: UnmatchedTcp,
}

impl TcpEgressPolicy {
    /// Resolve the launch bearer and bind it to every configured AWAF route.
    pub(crate) fn from_config(config: Option<&TcpEgressConfig>) -> io::Result<Self> {
        let Some(config) = config else {
            return Ok(Self::direct());
        };
        config.validate()?;
        let bearer = if config.access_flow_routes.is_empty() {
            None
        } else {
            load_bearer(
                env::var_os(AWAF_BEARER_ENV),
                env::var_os(AWAF_BEARER_FILE_ENV),
            )?
            .map(Arc::new)
        };
        if bearer.is_none()
            && config
                .access_flow_routes
                .values()
                .any(AccessFlowEndpoint::requires_bearer)
        {
            return Err(invalid_config(format!(
                "AWAF TLS routes require a bearer in {AWAF_BEARER_ENV} or {AWAF_BEARER_FILE_ENV}"
            )));
        }
        let access_flow_routes = config
            .access_flow_routes
            .iter()
            .map(|(&port, endpoint)| {
                let endpoint = prepare_endpoint(endpoint)?;
                Ok((
                    port,
                    Arc::new(AccessFlowProxy {
                        endpoint,
                        bearer: bearer.as_ref().map(Arc::clone),
                    }),
                ))
            })
            .collect::<io::Result<_>>()?;

        Ok(Self {
            access_flow_routes,
            direct_ports: config.direct_ports.clone(),
            unmatched: config.unmatched,
        })
    }

    pub(crate) fn direct() -> Self {
        Self {
            access_flow_routes: BTreeMap::new(),
            direct_ports: BTreeSet::new(),
            unmatched: UnmatchedTcp::Direct,
        }
    }

    pub(crate) fn route(&self, destination: SocketAddr) -> TcpRoute {
        if let Some(proxy) = self.access_flow_routes.get(&destination.port()) {
            if !destination.is_ipv4() {
                return TcpRoute::Deny;
            }
            return TcpRoute::AccessFlow(Arc::clone(proxy));
        }
        if self.direct_ports.contains(&destination.port()) {
            return TcpRoute::Direct;
        }
        match self.unmatched {
            UnmatchedTcp::Direct => TcpRoute::Direct,
            UnmatchedTcp::Deny => TcpRoute::Deny,
        }
    }
}

fn encode_preface(
    destination: SocketAddr,
    bearer: Option<&[u8]>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let IpAddr::V4(address) = destination.ip() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AWAF v1 only supports IPv4 destinations",
        ));
    };
    if address.is_unspecified()
        || address.is_multicast()
        || address == std::net::Ipv4Addr::BROADCAST
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "AWAF v1 destination IPv4 address is not connectable",
        ));
    }
    if let Some(bearer) = bearer {
        validate_bearer(bearer)?;
    }

    let bearer_len = bearer.map_or(0, <[u8]>::len);
    let presentation = if bearer.is_some() { 0x02 } else { 0x01 };
    let mut preface = Zeroizing::new(Vec::with_capacity(ACCESS_FLOW_HEADER_LEN + bearer_len));
    preface.extend_from_slice(b"AWAF");
    preface.extend_from_slice(&[0x01, 0x01, 0x01, presentation]);
    preface.extend_from_slice(&destination.port().to_be_bytes());
    preface.extend_from_slice(&address.octets());
    preface.extend_from_slice(&(bearer_len as u16).to_be_bytes());
    if let Some(bearer) = bearer {
        preface.extend_from_slice(bearer);
    }
    Ok(preface)
}

fn validate_port(port: u16, route: &str) -> io::Result<()> {
    if port == 0 {
        return Err(invalid_config(format!("{route} cannot use TCP port 0")));
    }
    Ok(())
}

fn validate_socket_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(invalid_config(
            "AWAF routes require an absolute Unix socket path",
        ));
    }
    Ok(())
}

fn validate_tls_address(address: &str) -> io::Result<()> {
    let (host, port) = split_tls_address(address)?;
    if port == 0 {
        return Err(invalid_config("AWAF TLS address cannot use TCP port 0"));
    }
    validate_host(host, "AWAF TLS address")
}

fn validate_server_name(server_name: &str) -> io::Result<()> {
    validate_host(server_name, "AWAF TLS server name")?;
    ServerName::try_from(server_name.to_owned())
        .map(|_| ())
        .map_err(|_| invalid_config("AWAF TLS server name is invalid"))
}

fn validate_host(host: &str, field: &str) -> io::Result<()> {
    if host.is_empty()
        || host.contains(|character: char| {
            character.is_ascii_whitespace() || matches!(character, '/' | '?' | '#' | '@')
        })
    {
        return Err(invalid_config(format!("{field} is invalid")));
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        let invalid = address.is_unspecified()
            || address.is_multicast()
            || matches!(address, IpAddr::V4(address) if address == std::net::Ipv4Addr::BROADCAST);
        if invalid {
            return Err(invalid_config(format!("{field} is not connectable")));
        }
        return Ok(());
    }
    match ServerName::try_from(host.to_owned()) {
        Ok(ServerName::DnsName(_)) => Ok(()),
        _ => Err(invalid_config(format!("{field} is invalid"))),
    }
}

fn split_tls_address(address: &str) -> io::Result<(&str, u16)> {
    if let Some(remainder) = address.strip_prefix('[') {
        let (host, port) = remainder
            .split_once("]:")
            .ok_or_else(|| invalid_config("AWAF TLS IPv6 address must use [HOST]:PORT"))?;
        let port = port
            .parse::<u16>()
            .map_err(|_| invalid_config("AWAF TLS address has an invalid port"))?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| invalid_config("AWAF TLS address has invalid bracketed IPv6"))?;
        return Ok((host, port));
    }
    let (host, port) = address
        .rsplit_once(':')
        .ok_or_else(|| invalid_config("AWAF TLS address must be HOST:PORT"))?;
    if host.contains(':') {
        return Err(invalid_config("AWAF TLS IPv6 address must use [HOST]:PORT"));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| invalid_config("AWAF TLS address has an invalid port"))?;
    Ok((host, port))
}

fn validate_trust_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(invalid_config(
            "AWAF TLS trust bundle requires an absolute file path",
        ));
    }
    Ok(())
}

fn prepare_endpoint(endpoint: &AccessFlowEndpoint) -> io::Result<PreparedAccessFlowEndpoint> {
    match endpoint {
        AccessFlowEndpoint::Unix { path } => {
            #[cfg(unix)]
            {
                Ok(PreparedAccessFlowEndpoint::Unix(path.clone()))
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "AWAF Unix socket egress is unsupported on this host; use tls://",
                ))
            }
        }
        AccessFlowEndpoint::TlsTcp {
            address,
            server_name,
            trust_path,
        } => Ok(PreparedAccessFlowEndpoint::TlsTcp {
            addresses: resolve_tls_addresses(address)?,
            server_name: ServerName::try_from(server_name.clone())
                .map_err(|_| invalid_config("AWAF TLS server name is invalid"))?,
            client_config: load_tls_client_config(trust_path)?,
        }),
    }
}

fn load_tls_client_config(path: &Path) -> io::Result<Arc<ClientConfig>> {
    let pem = read_stable_trust_file(path)?;
    if pem.is_empty() {
        return Err(invalid_config(format!(
            "AWAF TLS trust bundle {} must be a nonempty regular file no larger than {MAX_TRUST_FILE_BYTES} bytes",
            path.display()
        )));
    }

    let items = rustls_pemfile::read_all(&mut BufReader::new(Cursor::new(pem)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid_config("AWAF TLS trust bundle contains invalid PEM"))?;
    if items.is_empty() || items.len() > MAX_TRUST_CERTIFICATES {
        return Err(invalid_config(format!(
            "AWAF TLS trust bundle must contain 1 through {MAX_TRUST_CERTIFICATES} certificates"
        )));
    }

    let mut certificates = Vec::with_capacity(items.len());
    for item in items {
        let rustls_pemfile::Item::X509Certificate(certificate) = item else {
            return Err(invalid_config(
                "AWAF TLS trust bundle may contain only CERTIFICATE PEM blocks",
            ));
        };
        if certificate.len() > MAX_TRUST_CERTIFICATE_BYTES {
            return Err(invalid_config(format!(
                "AWAF TLS trust certificate exceeds {MAX_TRUST_CERTIFICATE_BYTES} bytes"
            )));
        }
        certificates.push(certificate);
    }

    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| invalid_config("AWAF TLS trust bundle contains an invalid certificate"))?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| invalid_config(format!("build AWAF TLS policy: {error}")))?;
    let mut config = builder.with_root_certificates(roots).with_no_client_auth();
    config.alpn_protocols = vec![ACCESS_FLOW_TLS_ALPN.to_vec()];
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    config.enable_secret_extraction = false;
    config.cert_compressors.clear();
    config.cert_decompressors.clear();
    Ok(Arc::new(config))
}

fn read_stable_trust_file(path: &Path) -> io::Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("inspect AWAF TLS trust bundle {}: {error}", path.display()),
        )
    })?;
    if path_metadata.file_type().is_symlink() {
        return Err(invalid_config(format!(
            "AWAF TLS trust bundle {} must not be a symbolic link",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if path_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid_config(format!(
                "AWAF TLS trust bundle {} must not be a reparse point",
                path.display()
            )));
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("open AWAF TLS trust bundle {}: {error}", path.display()),
        )
    })?;
    let before = file.metadata()?;
    validate_trust_metadata(path, &before)?;

    let mut pem = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_TRUST_FILE_BYTES + 1)
        .read_to_end(&mut pem)?;
    if pem.len() as u64 > MAX_TRUST_FILE_BYTES {
        return Err(invalid_config(format!(
            "AWAF TLS trust bundle {} exceeds {MAX_TRUST_FILE_BYTES} bytes",
            path.display()
        )));
    }
    let after = file.metadata()?;
    if !same_file_snapshot(&before, &after) {
        return Err(invalid_config(format!(
            "AWAF TLS trust bundle {} changed while being read",
            path.display()
        )));
    }
    Ok(pem)
}

fn validate_trust_metadata(path: &Path, metadata: &std::fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_TRUST_FILE_BYTES {
        return Err(invalid_config(format!(
            "AWAF TLS trust bundle {} must be a nonempty regular file no larger than {MAX_TRUST_FILE_BYTES} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        let owner = metadata.uid();
        let current = unsafe { libc::geteuid() };
        if owner != current && owner != 0 {
            return Err(invalid_config(format!(
                "AWAF TLS trust bundle {} must be owned by the current user or root",
                path.display()
            )));
        }
        if metadata.mode() & 0o022 != 0 || metadata.nlink() != 1 {
            return Err(invalid_config(format!(
                "AWAF TLS trust bundle {} must not be group/world writable or hard-linked",
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_file_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.created().ok() == after.created().ok()
}

fn resolve_tls_addresses(address: &str) -> io::Result<Vec<SocketAddr>> {
    let mut addresses = address.to_socket_addrs().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("resolve AWAF TLS address {address}: {error}"),
        )
    })?;
    let resolved = addresses.by_ref().take(9).collect::<Vec<_>>();
    if resolved.is_empty() {
        return Err(invalid_config(format!(
            "AWAF TLS address {address} resolved to no addresses"
        )));
    }
    if resolved.len() > 8 {
        return Err(invalid_config(format!(
            "AWAF TLS address {address} resolved to more than 8 addresses"
        )));
    }
    Ok(resolved)
}

fn connect_tls(
    addresses: &[SocketAddr],
    server_name: ServerName<'static>,
    client_config: Arc<ClientConfig>,
    preface: &[u8],
) -> io::Result<TlsStream> {
    let deadline = Instant::now() + ACCESS_FLOW_SETUP_TIMEOUT;
    let mut last_error = None;
    let mut tcp = None;
    for socket_address in addresses {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(socket_address, remaining) {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let tcp = tcp.ok_or_else(|| {
        last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "connect to AWAF TLS address timed out",
            )
        })
    })?;
    tcp.set_nodelay(true)?;
    tcp.set_nonblocking(true)?;

    let connection = ClientConnection::new(client_config, server_name)
        .map_err(|error| invalid_config(format!("create AWAF TLS client: {error}")))?;
    let mut stream = StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        ensure_setup_time(deadline)?;
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    if stream.conn.alpn_protocol() != Some(ACCESS_FLOW_TLS_ALPN) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AWAF TLS peer did not negotiate aw-access-flow/1",
        ));
    }
    if stream.conn.protocol_version() != Some(ProtocolVersion::TLSv1_3)
        || !matches!(
            stream.conn.handshake_kind(),
            Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "AWAF TLS peer did not complete the required full TLS 1.3 handshake",
        ));
    }
    write_all_until(&mut stream, preface, deadline)?;
    flush_until(&mut stream, deadline)?;
    Ok(stream)
}

fn ensure_setup_time(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "AWAF TLS setup timed out",
        ));
    }
    Ok(())
}

fn write_all_until(stream: &mut TlsStream, mut input: &[u8], deadline: Instant) -> io::Result<()> {
    while !input.is_empty() {
        ensure_setup_time(deadline)?;
        match stream.write(input) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => input = &input[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn flush_until(stream: &mut TlsStream, deadline: Instant) -> io::Result<()> {
    loop {
        ensure_setup_time(deadline)?;
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
}

fn load_bearer(
    direct: Option<OsString>,
    file: Option<OsString>,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let bearer = if let Some(value) = direct {
        let value = value
            .into_string()
            .map_err(|_| invalid_config(format!("{AWAF_BEARER_ENV} is not valid UTF-8")))?;
        Zeroizing::new(value.into_bytes())
    } else if let Some(path) = file {
        Zeroizing::new(std::fs::read(PathBuf::from(path))?)
    } else {
        return Ok(None);
    };
    validate_bearer(&bearer)?;
    Ok(Some(bearer))
}

fn validate_bearer(bearer: &[u8]) -> io::Result<()> {
    if bearer.len() < MIN_BEARER_LEN
        || bearer.len() > MAX_BEARER_LEN
        || !bearer.iter().copied().all(is_tchar)
    {
        return Err(invalid_config(format!(
            "AWAF bearer must contain {MIN_BEARER_LEN} through {MAX_BEARER_LEN} ASCII token characters"
        )));
    }
    Ok(())
}

const fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn invalid_config(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{ServerConfig, ServerConnection};
    #[cfg(unix)]
    use std::net::Ipv6Addr;
    use std::net::{Ipv4Addr, TcpListener};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;
    use std::thread;

    const BEARER: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

    fn absolute_test_path(name: &str) -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(format!(r"C:\smolvm-tests\{name}"))
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/tmp").join(name)
        }
    }

    #[cfg(unix)]
    fn config() -> TcpEgressConfig {
        TcpEgressConfig::new(
            BTreeMap::from([
                (
                    80,
                    AccessFlowEndpoint::unix(PathBuf::from("/tmp/http.sock")).unwrap(),
                ),
                (
                    443,
                    AccessFlowEndpoint::unix(PathBuf::from("/tmp/https.sock")).unwrap(),
                ),
            ]),
            BTreeSet::from([22]),
            UnmatchedTcp::Deny,
        )
        .unwrap()
    }

    #[cfg(unix)]
    fn policy() -> TcpEgressPolicy {
        let bearer = Arc::new(Zeroizing::new(BEARER.as_bytes().to_vec()));
        TcpEgressPolicy {
            access_flow_routes: config()
                .access_flow_routes
                .into_iter()
                .map(|(port, endpoint)| {
                    (
                        port,
                        Arc::new(AccessFlowProxy {
                            endpoint: prepare_endpoint(&endpoint).unwrap(),
                            bearer: Some(Arc::clone(&bearer)),
                        }),
                    )
                })
                .collect(),
            direct_ports: BTreeSet::from([22]),
            unmatched: UnmatchedTcp::Deny,
        }
    }

    #[test]
    #[cfg(unix)]
    fn routes_configured_ports_and_denies_unmatched_tcp() {
        let policy = policy();
        assert!(matches!(
            policy.route(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 80)),
            TcpRoute::AccessFlow(_)
        ));
        assert!(matches!(
            policy.route(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 22)),
            TcpRoute::Direct
        ));
        assert!(matches!(
            policy.route(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 25)),
            TcpRoute::Deny
        ));
        assert!(matches!(
            policy.route(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 443)),
            TcpRoute::Deny
        ));
    }

    #[test]
    fn direct_bearer_takes_precedence_over_file() {
        let bearer = load_bearer(
            Some(OsString::from(BEARER)),
            Some(OsString::from("/path/that/does/not/exist")),
        )
        .unwrap();
        assert_eq!(bearer.unwrap().as_slice(), BEARER.as_bytes());
    }

    #[test]
    fn bearer_file_is_used_when_direct_value_is_absent() {
        let path = std::env::temp_dir().join(format!("smolvm-awaf-bearer-{}", std::process::id()));
        std::fs::write(&path, BEARER).unwrap();
        let bearer = load_bearer(None, Some(path.clone().into_os_string())).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(bearer.unwrap().as_slice(), BEARER.as_bytes());
    }

    #[test]
    fn overlapping_routes_are_rejected() {
        let error = TcpEgressConfig::new(
            BTreeMap::from([(
                443,
                AccessFlowEndpoint::TlsTcp {
                    address: "127.0.0.1:7444".to_string(),
                    server_name: "proxy.example.test".to_string(),
                    trust_path: absolute_test_path("proxy-roots.pem"),
                },
            )]),
            BTreeSet::from([443]),
            UnmatchedTcp::Deny,
        )
        .unwrap_err();
        assert!(error.to_string().contains("both AWAF and direct"));
    }

    #[test]
    fn validates_tls_endpoint_fields() {
        let endpoint = AccessFlowEndpoint::tls_tcp(
            "127.0.0.1:7443".to_string(),
            "proxy.example.test".to_string(),
            absolute_test_path("proxy-roots.pem"),
        )
        .unwrap();
        assert_eq!(
            endpoint,
            AccessFlowEndpoint::TlsTcp {
                address: "127.0.0.1:7443".to_string(),
                server_name: "proxy.example.test".to_string(),
                trust_path: absolute_test_path("proxy-roots.pem"),
            }
        );

        assert!(AccessFlowEndpoint::tls_tcp(
            "127.0.0.1".to_string(),
            "proxy.example.test".to_string(),
            absolute_test_path("proxy-roots.pem"),
        )
        .is_err());
        assert!(AccessFlowEndpoint::tls_tcp(
            "127.0.0.1:7443".to_string(),
            "*.example.test".to_string(),
            absolute_test_path("proxy-roots.pem"),
        )
        .is_err());
        assert!(AccessFlowEndpoint::tls_tcp(
            "127.0.0.1:7443".to_string(),
            "proxy.example.test".to_string(),
            PathBuf::from("relative.pem"),
        )
        .is_err());
    }

    #[test]
    fn tls_connector_trusts_explicit_self_signed_certificate_and_sends_preface() {
        let generated =
            rcgen::generate_simple_self_signed(vec!["proxy.example.test".to_string()]).unwrap();
        let trust_path = std::env::temp_dir().join(format!(
            "smolvm-awaf-self-signed-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&trust_path, generated.cert.pem()).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&trust_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap();
        let private_key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(generated.key_pair.serialize_der()));
        let mut server_config = builder
            .with_no_client_auth()
            .with_single_cert(vec![generated.cert.der().clone()], private_key)
            .unwrap();
        server_config.alpn_protocols = vec![ACCESS_FLOW_TLS_ALPN.to_vec()];

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
            let mut stream = StreamOwned::new(connection, tcp);
            let mut preface = vec![0u8; ACCESS_FLOW_HEADER_LEN + BEARER.len()];
            stream.read_exact(&mut preface).unwrap();
            let mut request = [0u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
            stream.flush().unwrap();
            preface
        });

        let proxy = AccessFlowProxy {
            endpoint: PreparedAccessFlowEndpoint::TlsTcp {
                addresses: vec![address],
                server_name: ServerName::try_from("proxy.example.test".to_string()).unwrap(),
                client_config: load_tls_client_config(&trust_path).unwrap(),
            },
            bearer: Some(Arc::new(Zeroizing::new(BEARER.as_bytes().to_vec()))),
        };
        let destination = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 443);
        let mut stream = proxy.connect(destination).unwrap();
        stream.write_all(b"ping").unwrap();
        stream.flush().unwrap();
        let mut response = [0u8; 4];
        loop {
            match stream.read_exact(&mut response) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("read TLS response: {error}"),
            }
        }
        assert_eq!(&response, b"pong");
        drop(stream);

        let received = server.join().unwrap();
        let expected = encode_preface(destination, Some(BEARER.as_bytes())).unwrap();
        assert_eq!(received, expected.as_slice());
        std::fs::remove_file(trust_path).unwrap();
    }

    #[test]
    fn invalid_bearer_does_not_fall_back_to_file() {
        let error = load_bearer(
            Some(OsString::from("short")),
            Some(OsString::from("/path/that/does/not/exist")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("AWAF bearer must contain"));
    }

    #[test]
    fn missing_bearer_selects_anonymous_presentation() {
        assert!(load_bearer(None, None).unwrap().is_none());

        let destination = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 443);
        let encoded = encode_preface(destination, None).unwrap();
        assert_eq!(
            encoded.as_slice(),
            [
                0x41, 0x57, 0x41, 0x46, 0x01, 0x01, 0x01, 0x01, 0x01, 0xbb, 0xc0, 0x00, 0x02, 0x0a,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn encodes_canonical_awaf_bearer_preface() {
        let destination = SocketAddr::new(Ipv4Addr::new(192, 0, 2, 10).into(), 443);
        let encoded = encode_preface(destination, Some(BEARER.as_bytes())).unwrap();
        let mut expected = vec![
            0x41, 0x57, 0x41, 0x46, 0x01, 0x01, 0x01, 0x02, 0x01, 0xbb, 0xc0, 0x00, 0x02, 0x0a,
            0x00, 0x20,
        ];
        expected.extend_from_slice(BEARER.as_bytes());
        assert_eq!(encoded.as_slice(), expected);
    }

    #[test]
    fn rejects_non_connectable_awaf_destinations() {
        for address in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            let destination = SocketAddr::new(address.into(), 443);
            assert!(encode_preface(destination, Some(BEARER.as_bytes())).is_err());
        }
    }
}
