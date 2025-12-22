package grpc

import (
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

type Module struct{}

func (m *Module) NewFlags() any              { return new(Flags) }
func (m *Module) NewScanner() zgrab2.Scanner { return new(Scanner) }
func (m *Module) Description() string {
	return "Probe gRPC Server Reflection over HTTP/2 and collect headers/trailers and (if available) the first reflection response."
}

// RegisterModule registers this module with zgrab2.
func RegisterModule() {
	var module Module
	cmd, err := zgrab2.AddCommand(
		"grpc",
		"gRPC Server Reflection (HTTP/2)",
		module.Description(),
		0, // default port; we'll set it dynamically in Init()
		&module,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Remove default port so Init() can choose based on TLS/plaintext mode.
	cmd.FindOptionByLongName("port").Default = nil
	cmd.FindOptionByLongName("port").Description =
		"Target port (default: 80 for plaintext, 443 when used with --use-tls)"
}

// Auto-register when the package is compiled into the binary.
func init() {
	RegisterModule()
}
