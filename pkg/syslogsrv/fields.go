package syslogsrv

import (
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// Fields returns the list of extractor fields exported from syslog events.
func (p *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "syslogsrv.message", Desc: "The actual syslog message"},
		{Type: "string", Name: "syslogsrv.timestamp", Desc: "When the event occurred"},
		{Type: "string", Name: "syslogsrv.hostname", Desc: "Source host"},
		{Type: "uint64", Name: "syslogsrv.priority", Desc: "How urgent is the event"},
		{Type: "uint64", Name: "syslogsrv.facility", Desc: "A facility code is used to specify the type of system that is logging the message"},
		{Type: "uint64", Name: "syslogsrv.severity", Desc: "An impact that the event can cause"},
	}
}
