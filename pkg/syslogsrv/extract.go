package syslogsrv

import (
	"encoding/json"
	"io"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"gopkg.in/mcuadros/go-syslog.v2/format"
)

// Extract allows Falco plugin framework to get values for all available fields
func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	rawData, err := io.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	var logParts format.LogParts

	err = json.Unmarshal(rawData, &logParts)
	if err != nil {
		return err
	}

	switch req.Field() {
	case "syslogsrv.timestamp":
		req.SetValue(formatString(logParts["timestamp"]))
	case "syslogsrv.hostname":
		req.SetValue(formatString(logParts["hostname"]))
	case "syslogsrv.priority":
		req.SetValue(formatInt(logParts["priority"]))
	case "syslogsrv.facility":
		req.SetValue(formatInt(logParts["facility"]))
	case "syslogsrv.severity":
		req.SetValue(formatInt(logParts["severity"]))
	case "syslogsrv.message":
		if data, ok := logParts["content"]; ok {
			req.SetValue(formatString(data))
		} else {
			req.SetValue(formatString(logParts["message"]))
		}
	}

	return nil
}

func formatInt(i interface{}) uint64 {
	if i == nil {
		return 0
	}

	ci, ok := i.(int)
	if !ok {
		return 0
	}

	return uint64(ci)
}

func formatString(i interface{}) string {
	if i == nil {
		return ""
	}

	ci, ok := i.(string)
	if !ok {
		return ""
	}

	return ci
}
