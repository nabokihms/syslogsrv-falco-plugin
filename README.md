# Syslog Server Falco Plugin

## Introduction

The Syslog Server Falco Plugin is a powerful and essential tool designed to seamlessly make Falco, the cloud-native runtime security tool, accept events as a Syslog server.
This plugin allows security teams and system administrators to gain deeper insights into the security posture of their containerized environments by analyzing events usually sent to syslog, e.g., ssh auths events.

The plugin was tested with [Falco 0.35.1](https://github.com/falcosecurity/falco/releases/tag/0.35.1).

### Functionality

By using this plugin, Falco can pretend to be a syslog server and accept all events using the syslog protocol (RFC3164, RFC5424, and RFC6587 are supported).

## Capabilities

The `syslogsrv` plugin implements both the event sourcing and the field extraction capabilities of the Falco Plugin System.

### Event Source

The event source for Kubernetes Audit Events is `syslogsrv`.

### Supported Fields

<!-- README-PLUGIN-FIELDS -->
| NAME                  | TYPE     | ARG  | DESCRIPTION                                                                       |
|-----------------------|----------|------|-----------------------------------------------------------------------------------|
| `syslogsrv.timestamp` | `string` | None | When the event occurred                                                           |
| `syslogsrv.hostname`  | `string` | None | Source host                                                                       |
| `syslogsrv.message`   | `string` | None | The actual syslog message                                                         |
| `syslogsrv.priority`  | `int`    | None | How urgent is the event                                                           |
| `syslogsrv.facility`  | `int`    | None | A facility code is used to specify the type of system that is logging the message |
| `syslogsrv.severity`  | `int`    | None | An impact that the event can cause                                                |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: syslogsrv
    library_path: libsyslogsrv.so
    init_config:
      sslCertificate: /etc/falco/falco.pem
      format: "RFC6587"
    open_params: "udp://127.0.0.1:30514"

load_plugins: [syslogsrv]
```

**Initialization Config**:
- `sslCertificate`: The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem)
- `maxEventSize`: Maximum size of single audit event (Default: 262144)
- `format`: Which syslog format to use to parse messages (Default: RFC3164)
- `useAsync`: If true then async extraction optimization is enabled (Default: true)

**Open Parameters**:
- `udp://<host>:<port>`: Opens a UDP syslog server
- `tcp://<host>:<port>`: Opens a TCP syslog server
- `unixgram://socket.path`: Open a syslog server and accept events using the unixgram file socket


### Rules

TODO
