package syslogsrv

import (
	"encoding/json"
	"log"
	"os"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/invopop/jsonschema"
)

const pluginName = "syslogsrv"

// Plugin implements extractor.Plugin and reads syslog events.
type Plugin struct {
	plugins.BasePlugin
	logger       *log.Logger
	Config       PluginConfig
	lastEventNum uint64
}

func (p *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        pluginName,
		Description: "Pretends to be a syslog server and analyze events",
		Contact:     "github.com/falcosecurity/plugins",
		Version:     "0.0.1",
		EventSource: "syslog",
	}
}

func (p *Plugin) Init(cfg string) error {
	// read configuration
	p.Config.Reset()
	err := json.Unmarshal([]byte(cfg), &p.Config)
	if err != nil {
		return err
	}

	extract.SetAsync(p.Config.UseAsync)

	// setup internal logger
	p.logger = log.New(os.Stderr, "["+pluginName+"] ", log.LstdFlags|log.LUTC|log.Lmsgprefix)
	return nil
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}
