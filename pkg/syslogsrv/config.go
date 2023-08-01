package syslogsrv

import "github.com/falcosecurity/plugin-sdk-go/pkg/sdk"

type PluginConfig struct {
	SSLCertificate string `json:"sslCertificate"       jsonschema:"title=SSL certificate,description=The SSL Certificate to be used with the TLS endpoint (Example: /etc/falco/falco.pem),default="`
	MaxEventSize   uint64 `json:"maxEventSize"         jsonschema:"title=Maximum event size,description=Maximum size of single event (Default: 262144),default=262144"`
	UseAsync       bool   `json:"useAsync"             jsonschema:"title=Use async extraction,description=If true then async extraction optimization is enabled (Default: true),default=true"`
	Format         string `json:"format"         jsonschema:"title=Syslog Parser,description=Which syslog format to use to parse messages (Available options: RFC3164 or RFC5424 or RFC6587),default=RFC3164,enum=RFC3164,enum=RFC5424,enum=RFC6587"`
}

// Reset sets the configuration to its default values
func (p *PluginConfig) Reset() {
	p.SSLCertificate = ""
	p.MaxEventSize = uint64(sdk.DefaultEvtSize)
	p.UseAsync = true
	p.Format = "RFC3164"
}
