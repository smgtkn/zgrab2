package grpc

import (
	"strings"

	"github.com/zmap/zgrab2"
)

type Module struct{}

func (m *Module) NewFlags() any {
	return new(Flags)
}

func (m *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

func (m *Module) Description() string {
	return strings.Join([]string{
		"Probe gRPC Server Reflection over HTTP/2 (TLS or plaintext).",
		"Sends a single ServerReflectionInfo(ListServices='*') request and captures first response and headers/trailers.",
	}, "\n")
}
