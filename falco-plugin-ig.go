/*
Copyright (C) 2022 The Falco Authors.
Copyright (C) 2023 The Inspektor Gadget authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This plugin is a simple example of plugin with both event sourcing and
// field extraction capabilities.
// The plugin produces events of the "example" data source containing
// a single uint64 representing the incrementing value of a counter,
// serialized using a encoding/gob encoder. The plugin is capable of
// extracting the "example.count" and "example.countstr" fields from the
// "example" event source, which are simple numeric and string representations
// of the counter value.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
)

// Defining a type for the plugin configuration.
// In this simple example, users can define the starting value the event
// counter. the `jsonschema` tags is used to automatically generate a
// JSON Schema definition, so that the framework can perform automatic
// validations.
type GadgetPluginConfig struct {
	Gadget string `json:"gadget" jsonschema:"title=gadget image,description=The gadget image"`
}

// Defining a type for the plugin.
// Composing the struct with plugins.BasePlugin is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in the plugin must be defined here.
type GadgetPlugin struct {
	plugins.BasePlugin
	config   GadgetPluginConfig
	initTime time.Time
}

// Defining a type for the plugin source capture instances returned by Open().
// Multiple instances of the same plugin can be opened at the same time for
// different capture sessions.
// Composing the struct with plugins.BaseInstance is the recommended practice
// as it provides the boilerplate code that satisfies most of the interface
// requirements of the SDK.
//
// State variables to store in each plugin instance must be defined here.
// In this example, we store the internal value of the incrementing counter.
type GadgetInstance struct {
	source.BaseInstance
	timeout       time.Duration
	timeoutTicker *time.Ticker
	gadgetImage   string
	tracer        *tracer.Tracer
	queue         chan *types.Event
}

// The plugin must be registered to the SDK in the init() function.
// Registering the plugin using both source.Register and extractor.Register
// declares to the SDK a plugin with both sourcing and extraction features
// enabled. The order in which the two Register functions are called is not
// relevant.
// This requires our plugin to implement the source.Plugin interface, so
// compilation will fail if the mandatory methods are not implemented.
func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &GadgetPlugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

// Info returns a pointer to a plugin.Info struct, containing all the
// general information about this plugin.
// This method is mandatory.
func (m *GadgetPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          999,
		Name:        "ig",
		Description: "Plugin fetching events from Inspektor Gadget",
		Contact:     "github.com/inspektor-gadget/falco-plugin-ig/",
		Version:     "0.1.0",
		EventSource: "ig",
	}
}

// InitSchema is gets called by the SDK before initializing the plugin.
// This returns a schema representing the configuration expected by the
// plugin to be passed to the Init() method. Defining InitSchema() allows
// the framework to automatically validate the configuration, so that the
// plugin can assume that it to be always be well-formed when passed to Init().
// This is ignored if the return value is nil. The returned schema must follow
// the JSON Schema specific. See: https://json-schema.org/
// This method is optional.
func (m *GadgetPlugin) InitSchema() *sdk.SchemaInfo {
	// We leverage the jsonschema package to autogenerate the
	// JSON Schema definition using reflection from our config struct.
	schema, err := jsonschema.Reflect(&GadgetPluginConfig{}).MarshalJSON()
	if err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

// Init initializes this plugin with a given config string.
// Since this plugin defines the InitSchema() method, we can assume
// that the configuration is pre-validated by the framework and
// always well-formed according to the provided schema.
// This method is mandatory.
func (m *GadgetPlugin) Init(config string) error {
	m.initTime = time.Now()
	// Deserialize the config json. Ignoring the error
	// and not validating the config values is possible
	// due to the schema defined through InitSchema(),
	// for which the framework performas a pre-validation.
	json.Unmarshal([]byte(config), &m.config)
	return nil
}

// Fields return the list of extractor fields exported by this plugin.
// This method is mandatory the field extraction capability.
// If the Fields method is defined, the framework expects an Extract method
// to be specified too.
func (m *GadgetPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "ig.gadget", Display: "Gadget name", Desc: "Name of the gadget that generated the event"},
		{Type: "string", Name: "ig.comm", Display: "Process name", Desc: "Name of the process"},
	}
}

// This method is mandatory the field extraction capability.
// If the Extract method is defined, the framework expects an Fields method
// to be specified too.
func (m *GadgetPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	rawData, err := io.ReadAll(evt.Reader())
	if err != nil {
		return err
	}
	var value types.Event
	err = json.Unmarshal(rawData, &value)
	if err != nil {
		return err
	}

	switch req.Field() {
	case "ig.gadget":
		req.SetValue("trace exec")
		return nil
	case "ig.comm":
		req.SetValue(value.Comm)
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

// OpenParams returns a list of suggested parameters that would be accepted
// as valid arguments to Open().
// This method is optional for the event sourcing capability.
func (m *GadgetPlugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{}, nil
}

// Open opens the plugin source and starts a new capture session (e.g. stream
// of events), creating a new plugin instance. The state of each instance can
// be initialized here. This method is mandatory for the event sourcing capability.
func (m *GadgetPlugin) Open(params string) (source.Instance, error) {
	// An event batch buffer can optionally be defined to specify custom
	// values for max data size or max batch size. If nothing is set
	// with the SetEvents method, the SDK will provide a default value
	// after the Open method returns.
	// In this example, we want to allocate a batch of max 10 events, each
	// one of max 64 bytes, which is more than enough to host the serialized
	// incrementing counter value.
	myBatch, err := sdk.NewEventWriters(10, int64(sdk.DefaultEvtSize))
	if err != nil {
		return nil, err
	}

	gadgetInstance := &GadgetInstance{
		gadgetImage: m.config.Gadget,
		queue:       make(chan *types.Event, 100),
		timeout:     30 * time.Millisecond,
	}

	eventCallback := func(event *types.Event) {
		gadgetInstance.queue <- event
	}

	tracer, err := tracer.NewTracer(&tracer.Config{}, nil, eventCallback)
	if err != nil {
		return nil, err
	}

	gadgetInstance.tracer = tracer
	gadgetInstance.SetEvents(myBatch)
	gadgetInstance.timeoutTicker = time.NewTicker(gadgetInstance.timeout)
	return gadgetInstance, nil
}

// String produces a string representation of an event data produced by the
// event source of this plugin.
// This method is optional for the event sourcing capability.
func (m *GadgetPlugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := io.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	return string(evtBytes), nil
}

// NextBatch produces a batch of new events, and is called repeatedly by the
// framework. For plugins with event sourcing capability, it's mandatory to
// specify a NextBatch method.
// The batch has a maximum size that dependes on the size of the underlying
// reusable memory buffer. A batch can be smaller than the maximum size.
func (m *GadgetInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// timeout needs to be resetted for this batch
	m.timeoutTicker.Reset(m.timeout)

	var n int
	var evt sdk.EventWriter
	for n = 0; n < evts.Len(); n++ {
		select {
		// an event is received, so we add it in the batch
		case e := <-m.queue:
			evt = evts.Get(n)
			jsonEvent, _ := json.Marshal(e)
			if _, err := evt.Writer().Write(jsonEvent); err != nil {
				return n, err
			}
			evt.SetTimestamp(uint64(e.Timestamp))
		// timeout hits, so we flush a partial batch
		case <-m.timeoutTicker.C:
			return n, sdk.ErrTimeout
		}
	}
	return n, nil
}

// Progress returns a percentage indicator referring to the production progress
// of the event source of this plugin.
// This method is optional for the event sourcing capability.
// func (m *GadgetInstance) Progress(pState sdk.PluginState) (float64, string) {
//
// }

// Close is gets called by the SDK when the plugin source capture gets closed.
// This is useful to release any open resource used by each plugin instance.
// This method is optional for the event sourcing capability.
func (m *GadgetInstance) Close() {
	m.timeoutTicker.Stop()
	m.tracer.Stop()
}

// Destroy is gets called by the SDK when the plugin gets deinitialized.
// This is useful to release any open resource used by the plugin.
// This method is optional.
// func (m *GadgetPlugin) Destroy() {
//
// }

func main() {}
