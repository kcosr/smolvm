# Published Unix sockets over the HTTP API

`POST /api/v1/machines` accepts a typed `publishedSockets` array for bridging
Unix sockets between the host and guest:

```json
{
  "name": "worker",
  "publishedSockets": [
    {
      "direction": "expose",
      "guestPath": "/run/worker.sock"
    },
    {
      "direction": "mount",
      "guestPath": "/run/control.sock",
      "hostPath": "/run/services/control.sock"
    }
  ]
}
```

`direction: "expose"` makes a socket listened to in the guest reachable from
the host. Its `hostPath` is optional; when omitted, smolvm uses the guest socket
basename in the machine's private data directory. `direction: "mount"` makes an
existing host-listening socket reachable in the guest and therefore requires
`hostPath`.

Create, get, and list responses return the same `direction` and `guestPath`, plus
a required `hostPath` containing the effective path. Callers should use that
reported path rather than deriving smolvm's private machine directory layout:

```json
{
  "publishedSockets": [
    {
      "direction": "expose",
      "guestPath": "/run/worker.sock",
      "hostPath": "/home/me/.cache/smolvm/vms/0123456789abcdef/worker.sock"
    }
  ]
}
```

Guest paths and explicit host paths must be absolute and may not contain NUL
bytes. A machine may configure at most 64 published sockets. Create rejects
exposed sockets that resolve to the same host listener, mounted sockets that
resolve to the same guest listener, cross-direction listener/dial-target
collisions, and mounted sockets without a host path.

The generated OpenAPI document (`smolvm serve openapi`) includes
`PublishedSocketSpec`, `PublishedSocketInfo`, and `PublishedSocketDirection`.
