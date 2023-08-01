package syslogsrv

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"gopkg.in/mcuadros/go-syslog.v2"
	"gopkg.in/mcuadros/go-syslog.v2/format"
)

// Open uses the following param examples:
//
//	udp://0.0.0.0:8000
//	tcp://127.0.0.1:443
//	unixgram://syslog.sock
func (p *Plugin) Open(params string) (source.Instance, error) {
	u, err := url.Parse(params)
	if err != nil {
		return nil, err
	}

	logPartsCh := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(logPartsCh)

	evtCh := make(chan source.PushEvent)

	server := syslog.NewServer()
	server.SetHandler(handler)

	switch p.Config.Format {
	case "RFC3164":
		server.SetFormat(&format.RFC3164{})
	case "RFC5424":
		server.SetFormat(&format.RFC5424{})
	case "RFC6587":
		server.SetFormat(&format.RFC6587{})
	default:
		return nil, fmt.Errorf("unknown syslog format: %v", p.Config.Format)
	}

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			data, err := json.Marshal(logParts)
			evtCh <- source.PushEvent{Data: data, Err: err}
		}
	}(logPartsCh)

	switch u.Scheme {
	case "udp":
		if err := server.ListenUDP(u.Host); err != nil {
			return nil, err
		}
	case "unixgram":
		if err := server.ListenUnixgram(u.Host + u.Query().Encode()); err != nil {
			return nil, err
		}
	case "tcp":
		if p.Config.SSLCertificate == "" {
			if err := server.ListenTCP(u.Host); err != nil {
				return nil, err
			}
		} else {
			certificates := make([]tls.Certificate, 1)
			certificates[0], err = tls.LoadX509KeyPair(p.Config.SSLCertificate, p.Config.SSLCertificate)
			if err != nil {
				return nil, err
			}

			tcfg := tls.Config{Certificates: certificates}

			if err := server.ListenTCPTLS(u.Host, &tcfg); err != nil {
				return nil, err
			}
		}
	}

	if err := server.Boot(); err != nil {
		return nil, err
	}

	return source.NewPushInstance(
		evtCh,
		source.WithInstanceClose(func() {
			_ = server.Kill()
			server.Wait()
		}),
		source.WithInstanceEventSize(uint32(p.Config.MaxEventSize)))
}
