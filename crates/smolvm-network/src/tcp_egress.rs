//! Configurable TCP egress routing for the virtio-net gateway.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fmt;
use std::io;
#[cfg(unix)]
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

/// Host environment variable containing the AWAF bearer directly.
pub const AWAF_BEARER_ENV: &str = "SMOLVM_AWAF_BEARER";
/// Host environment variable containing a path from which to read the AWAF bearer.
pub const AWAF_BEARER_FILE_ENV: &str = "SMOLVM_AWAF_BEARER_FILE";

const ACCESS_FLOW_HEADER_LEN: usize = 16;
const MIN_BEARER_LEN: usize = 32;
const MAX_BEARER_LEN: usize = 4096;
const ACCESS_FLOW_SETUP_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Persisted per-VM TCP routing configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpEgressConfig {
    access_flow_routes: BTreeMap<u16, PathBuf>,
    direct_ports: BTreeSet<u16>,
    #[serde(default)]
    unmatched: UnmatchedTcp,
}

impl TcpEgressConfig {
    /// Validate and construct one TCP routing configuration.
    pub fn new(
        access_flow_routes: BTreeMap<u16, PathBuf>,
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
        for (&port, path) in &self.access_flow_routes {
            validate_port(port, "AWAF route")?;
            validate_socket_path(path)?;
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

    /// AWAF destination-port to Unix-socket mappings.
    pub fn access_flow_routes(&self) -> &BTreeMap<u16, PathBuf> {
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
    socket_path: PathBuf,
    bearer: Option<Arc<Zeroizing<Vec<u8>>>>,
}

impl fmt::Debug for AccessFlowProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessFlowProxy")
            .field("socket_path", &self.socket_path)
            .field("authenticated", &self.bearer.is_some())
            .finish()
    }
}

impl AccessFlowProxy {
    #[cfg(unix)]
    pub(crate) fn connect(&self, destination: SocketAddr) -> io::Result<UnixStream> {
        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.set_write_timeout(Some(ACCESS_FLOW_SETUP_TIMEOUT))?;
        let preface = encode_preface(
            destination,
            self.bearer.as_ref().map(|bearer| bearer.as_slice()),
        )?;
        stream.write_all(preface.as_slice())?;
        stream.flush()?;
        stream.set_write_timeout(None)?;
        Ok(stream)
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
        #[cfg(not(unix))]
        if !config.access_flow_routes.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "AWAF Unix socket egress is unsupported on this host",
            ));
        }

        let bearer = if config.access_flow_routes.is_empty() {
            None
        } else {
            load_bearer(
                env::var_os(AWAF_BEARER_ENV),
                env::var_os(AWAF_BEARER_FILE_ENV),
            )?
            .map(Arc::new)
        };
        let access_flow_routes = config
            .access_flow_routes
            .iter()
            .map(|(&port, socket_path)| {
                (
                    port,
                    Arc::new(AccessFlowProxy {
                        socket_path: socket_path.clone(),
                        bearer: bearer.as_ref().map(Arc::clone),
                    }),
                )
            })
            .collect();

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
    use std::net::{Ipv4Addr, Ipv6Addr};

    const BEARER: &str = "abcdefghijklmnopqrstuvwxyzABCDEF";

    fn config() -> TcpEgressConfig {
        TcpEgressConfig::new(
            BTreeMap::from([
                (80, PathBuf::from("/tmp/http.sock")),
                (443, PathBuf::from("/tmp/https.sock")),
            ]),
            BTreeSet::from([22]),
            UnmatchedTcp::Deny,
        )
        .unwrap()
    }

    fn policy() -> TcpEgressPolicy {
        let bearer = Arc::new(Zeroizing::new(BEARER.as_bytes().to_vec()));
        TcpEgressPolicy {
            access_flow_routes: config()
                .access_flow_routes
                .into_iter()
                .map(|(port, socket_path)| {
                    (
                        port,
                        Arc::new(AccessFlowProxy {
                            socket_path,
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
            BTreeMap::from([(443, PathBuf::from("/tmp/https.sock"))]),
            BTreeSet::from([443]),
            UnmatchedTcp::Deny,
        )
        .unwrap_err();
        assert!(error.to_string().contains("both AWAF and direct"));
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
}
