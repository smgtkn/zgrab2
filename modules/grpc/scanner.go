package grpc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// Flags controls the probe behavior.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	UseTLS bool `long:"use-tls" description:"Use TLS for the connection (gRPC over h2)"`
	// If unset (0), we set defaults in Init().
	Timeout time.Duration `long:"timeout" default:"5s" description:"Overall per-target timeout (dial + probe)"`
	// If true, try v1 first, then v1alpha on UNIMPLEMENTED.
	TryV1Alpha bool `long:"try-v1alpha" default:"true" description:"If v1 reflection is UNIMPLEMENTED, try v1alpha"`
	// Optional override for :authority; otherwise Domain or IP is used.
	Authority string `long:"authority" description:"Override HTTP/2 :authority pseudo-header"`
	// Optional user-agent to send.
	UserAgent string `long:"user-agent" default:"zgrab2-grpc/0.x" description:"User-Agent header for gRPC probe"`
}

// Results is emitted as JSON under data.grpc.
type Results struct {
	UseTLS    bool   `json:"use_tls"`
	Scheme    string `json:"scheme"` // "http" or "https"
	ALPN      string `json:"alpn,omitempty"`
	Address   string `json:"address"`
	Authority string `json:"authority"`

	Attempts []AttemptResult `json:"attempts,omitempty"`
}

// AttemptResult captures one reflection attempt (v1 or v1alpha).
type AttemptResult struct {
	ReflectionService string `json:"reflection_service"` // "v1" or "v1alpha"
	Path              string `json:"path"`

	HTTPStatus int `json:"http_status,omitempty"`

	Headers  map[string][]string `json:"headers,omitempty"`
	Trailers map[string][]string `json:"trailers,omitempty"`

	// Parsed gRPC status if present
	GRPCStatus  *int32 `json:"grpc_status,omitempty"`
	GRPCMessage string `json:"grpc_message,omitempty"`

	// First reflection message, if decoded
	ReflectionResponseRawBase64 string   `json:"reflection_response_raw_base64,omitempty"`
	Services                    []string `json:"services,omitempty"`

	// Outcome
	Timeout bool   `json:"timeout,omitempty"`
	Error   string `json:"error,omitempty"`
}

type Scanner struct {
	cfg *Flags

	dialerGroupConfig *zgrab2.DialerGroupConfig
}

func (s *Scanner) Protocol() string { return "grpc" }

func (s *Scanner) GetDialerGroupConfig() *zgrab2.DialerGroupConfig {
	return s.dialerGroupConfig
}
func (flags *Flags) Help() string {
	lines := []string{
		"By default, the gRPC module will probe Server Reflection over HTTP/2 in plaintext and attempt to read the first reflection response message.",
		"Transport - gRPC requires HTTP/2. This module supports both plaintext (h2c prior-knowledge) and TLS (h2 via ALPN).",
		"",
		"Examples:",
		" - Plaintext gRPC reflection on port 50051 (default)      zgrab2 grpc --port 50051",
		" - TLS gRPC reflection (h2 via ALPN)                      zgrab2 grpc --use-tls --port 443",
		" - Override :authority (useful behind proxies)            zgrab2 grpc --authority \"example.com:6264\" --port 6264",
		" - Control overall timeout for the probe                  zgrab2 grpc --timeout 5s",
		"",
		"Behavior:",
		" - The scanner sends one ServerReflectionInfo request (ListServices='*').",
		" - If a reflection response arrives, it records the first message plus HTTP/2 headers/trailers.",
		" - If no message arrives before --timeout, it records any headers/trailers seen, cancels the stream, and closes the connection.",
		" - It tries grpc.reflection.v1 first and can fall back to v1alpha if the server reports UNIMPLEMENTED (grpc-status: 12).",
	}
	return strings.Join(lines, "\n")
}

// Validate performs any needed validation on the arguments
func (flags *Flags) Validate(_ []string) error {
	if flags.Timeout < 0 {
		return errors.New("--timeout must be >= 0")
	}
	return nil
}

func (s *Scanner) Init(flags zgrab2.ScanFlags) error {
	fl, ok := flags.(*Flags)
	if !ok {
		return errors.New("invalid flags type")
	}
	s.cfg = fl

	// Default port: if user didn't set --port
	if s.cfg.Port == 0 {
		if s.cfg.UseTLS {
			s.cfg.Port = 443
		} else {
			s.cfg.Port = 80
		}
	}

	// Ensure ALPN advertises h2 when using TLS unless user overrides NextProtos.
	// (TLSFlags.NextProtos is a comma-separated string in zgrab2)
	if s.cfg.UseTLS && len(s.cfg.NextProtos) == 0 {
		s.cfg.NextProtos = "h2"
	}

	s.dialerGroupConfig = &zgrab2.DialerGroupConfig{
		TransportAgnosticDialerProtocol: zgrab2.TransportTCP,
		NeedSeparateL4Dialer:            true,

		BaseFlags: &s.cfg.BaseFlags,

		// We want TLS capability, but we select TLS vs plaintext per-target based on UseTLS.
		TLSEnabled: true,
		TLSFlags:   &s.cfg.TLSFlags,
	}

	// Reduce noisy HTTP/2 logging if any internal libs are chatty.
	log.SetLevel(log.GetLevel())

	return nil
}

func (s *Scanner) InitPerSender(_ int) error { return nil }
func (s *Scanner) GetName() string           { return s.cfg.Name }
func (s *Scanner) GetTrigger() string        { return s.cfg.Trigger }
func (s *Scanner) GetScanMetadata() any      { return nil }

func (s *Scanner) Scan(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget) (zgrab2.ScanStatus, any, error) {
	if dialGroup == nil || dialGroup.L4Dialer == nil || dialGroup.TLSWrapper == nil {
		return zgrab2.SCAN_INVALID_INPUTS, nil, errors.New("dialGroup must include L4Dialer and TLSWrapper")
	}

	// Bound the whole scan with the module timeout (and any parent context deadline).
	timeout := s.cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	hostport := target.String() // usually "IP:port" or "domain:port"
	res := &Results{
		UseTLS:    s.cfg.UseTLS,
		Scheme:    ternary(s.cfg.UseTLS, "https", "http"),
		Address:   hostport,
		Authority: deriveAuthority(s.cfg.Authority, target),
	}

	// Attempt v1 first
	a1 := s.runAttempt(ctx, dialGroup, target, res.Authority, reflectionV1)
	res.Attempts = append(res.Attempts, a1)

	// If v1 says UNIMPLEMENTED and we’re allowed to try v1alpha, do that
	if s.cfg.TryV1Alpha && a1.GRPCStatus != nil && *a1.GRPCStatus == 12 {
		// Only try if we still have time left
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > 250*time.Millisecond {
			a2 := s.runAttempt(ctx, dialGroup, target, res.Authority, reflectionV1Alpha)
			res.Attempts = append(res.Attempts, a2)
		}
	}

	return zgrab2.SCAN_SUCCESS, res, nil
}

func (s *Scanner) runAttempt(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, authority string, which reflectionKind) AttemptResult {
	// Dial
	conn, alpn, dialErr := dialTarget(ctx, dialGroup, target, s.cfg.UseTLS)
	if dialErr != nil {
		return AttemptResult{
			ReflectionService: which.String(),
			Path:              which.Path(),
			Error:             dialErr.Error(),
		}
	}
	defer conn.Close()

	// Set deadlines so ReadFrame/Write doesn't hang beyond ctx
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Perform reflection probe over HTTP/2 frames
	ar := AttemptResult{
		ReflectionService: which.String(),
		Path:              which.Path(),
	}
	if alpn != "" {
		// Put ALPN info into attempt headers (lightweight)
		ar.Headers = map[string][]string{"_alpn": {alpn}}
	}

	out, err := probeReflectionOnce(ctx, conn, authority, s.cfg.UserAgent, which)
	if err != nil {
		// If ctx timed out, label it
		if errors.Is(err, context.DeadlineExceeded) {
			ar.Timeout = true
		}
		ar.Error = err.Error()
		mergeAttempt(&ar, out)
		return ar
	}

	mergeAttempt(&ar, out)
	return ar
}

func mergeAttempt(dst *AttemptResult, src AttemptResult) {
	// Merge maps carefully
	if src.HTTPStatus != 0 {
		dst.HTTPStatus = src.HTTPStatus
	}
	if src.Headers != nil {
		if dst.Headers == nil {
			dst.Headers = map[string][]string{}
		}
		for k, v := range src.Headers {
			dst.Headers[k] = v
		}
	}
	if src.Trailers != nil {
		dst.Trailers = src.Trailers
	}
	dst.GRPCStatus = src.GRPCStatus
	dst.GRPCMessage = src.GRPCMessage
	dst.ReflectionResponseRawBase64 = src.ReflectionResponseRawBase64
	dst.Services = src.Services
}

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func deriveAuthority(override string, target *zgrab2.ScanTarget) string {
	if override != "" {
		return override
	}
	if target.Domain != "" {
		return fmt.Sprintf("%s:%d", target.Domain, target.Port)
	}
	return fmt.Sprintf("%s:%d", target.IP.String(), target.Port)
}

// RegisterModule registers the gRPC reflection module with the zgrab2 framework.
func RegisterModule() {
	var module Module
	cmd, err := zgrab2.AddCommand(
		"grpc",
		"gRPC Server Reflection (HTTP/2)",
		module.Description(),
		0,
		&module,
	)
	if err != nil {
		log.Fatal(err)
	}

	// AddCommand sets a default port; we want to choose it dynamically in Init()
	// (e.g., 80 for plaintext, 443 for TLS), so remove the default.
	cmd.FindOptionByLongName("port").Default = nil

	// Provide a clearer port description for users.
	cmd.FindOptionByLongName("port").Description =
		"Target port (default: 80 for plaintext, 443 when used with --use-tls)"
}
