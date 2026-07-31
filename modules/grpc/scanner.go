package grpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
	"golang.org/x/net/http2"
)

// Flags controls the probe behavior.
type Flags struct {
	zgrab2.BaseFlags `group:"Basic Options"`
	zgrab2.TLSFlags  `group:"TLS Options"`

	UseTLS     bool          `long:"use-tls" description:"Use TLS for the connection (gRPC over h2)"`
	Timeout    time.Duration `long:"timeout" default:"5s" description:"Overall per-target timeout (dial + probe)"`
	TryV1Alpha bool          `long:"try-v1alpha" description:"If v1 reflection is UNIMPLEMENTED, try v1alpha"`
	Authority  string        `long:"authority" description:"Override HTTP/2 :authority pseudo-header"`
	UserAgent  string        `long:"user-agent" default:"zgrab2-grpc/0.x" description:"User-Agent header for gRPC probe"`
	// New flag for describe probing
	ProbeDescribe       bool          `long:"probe-describe" description:"Probe DescribeService for discovered services"`
	DescribeSingleConn  bool          `long:"describe-single-conn" description:"Re-use single HTTP/2 connection for all describe requests (default true)"`
	DescribeDelay       time.Duration `long:"describe-delay" default:"100ms" description:"Delay between describe requests to avoid overwhelming servers"`
	MaxDescribeServices int           `long:"max-describe-services" default:"0" description:"Maximum number of services to describe per target (0 = no limit)"`
}

// Results is emitted as JSON under data.grpc.
type Results struct {
	UseTLS    bool           `json:"use_tls"`
	Scheme    string         `json:"scheme"` // "http" or "https"
	Address   string         `json:"address"`
	Authority string         `json:"authority"`
	TLSLog    *zgrab2.TLSLog `json:"tls_log,omitempty"`

	Attempts []AttemptResult `json:"attempts,omitempty"`
}

// AttemptResult captures one reflection attempt (v1 or v1alpha).
type AttemptResult struct {
	ReflectionService string `json:"reflection_service"` // "v1" or "v1alpha"

	HTTPStatus int `json:"http_status,omitempty"`

	Headers  map[string][]string `json:"headers,omitempty"`
	Trailers map[string][]string `json:"trailers,omitempty"`

	// Parsed gRPC status if present
	GRPCStatus  *int32 `json:"grpc_status,omitempty"`
	GRPCMessage string `json:"grpc_message,omitempty"`

	// Reflection responses are captured and decoded to plaintext
	Services []string `json:"services,omitempty"`

	// Describe responses per service
	ServiceDescriptions map[string]ServiceDescription `json:"service_descriptions,omitempty"`

	// Outcome
	Timeout bool   `json:"timeout,omitempty"`
	Error   string `json:"error,omitempty"`
}

// ServiceDescription captures describe response data for a service.
// The service name is implicit as the map key.
type ServiceDescription struct {
	Descriptor  string `json:"descriptor,omitempty"`
	GRPCStatus  *int32 `json:"grpc_status,omitempty"`
	GRPCMessage string `json:"grpc_message,omitempty"`
	Error       string `json:"error,omitempty"`
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
		" - When --probe-describe is used, describe requests are sent for each service; by default they reuse the initial connection (use --describe-single-conn=false to dial per-service).",
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
	// default describe single connection to true if unset
	if !s.cfg.DescribeSingleConn {
		// user either explicitly set false or we treat zero value; we want true by default
		s.cfg.DescribeSingleConn = true
	}

	// Default port: if user didn't set --port
	if s.cfg.Port == 0 {
		if s.cfg.UseTLS {
			s.cfg.Port = 443
		} else {
			s.cfg.Port = 50051 //Default grpc port
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

	a1, tlsLog := s.runAttempt(ctx, dialGroup, target, res.Authority, reflectionV1)
	res.Attempts = append(res.Attempts, a1)

	// If v1 says UNIMPLEMENTED and we’re allowed to try v1alpha, do that
	if s.cfg.TryV1Alpha && a1.GRPCStatus != nil && *a1.GRPCStatus == 12 {

		//TODO: need to update this to try unless there is any respose to first attempt, because some servers may not return any grpc-status
		// Only try if we still have time left
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) > 250*time.Millisecond {
			a2, tlsLog := s.runAttempt(ctx, dialGroup, target, res.Authority, reflectionV1Alpha)
			res.Attempts = append(res.Attempts, a2)
			if tlsLog != nil {
				res.TLSLog = tlsLog

			}
		}
	}

	res.TLSLog = tlsLog

	return zgrab2.SCAN_SUCCESS, res, nil
}

func (s *Scanner) runAttempt(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, authority string, which reflectionKind) (AttemptResult, *zgrab2.TLSLog) {
	// Dial
	conn, tlsLog, dialErr := dialTarget(ctx, dialGroup, target, s.cfg.UseTLS)
	if dialErr != nil {
		return AttemptResult{
			ReflectionService: which.String(),
			Error:             dialErr.Error(),
		}, tlsLog
	}
	defer conn.Close()

	// Set deadlines so ReadFrame/Write doesn't hang beyond ctx
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	// Perform reflection probe over HTTP/2 frames
	ar := AttemptResult{
		ReflectionService: which.String(),
	}

	out, err := probeReflectionOnce(ctx, conn, authority, s.cfg.UserAgent, which)
	if err != nil {
		// If ctx timed out, label it
		if errors.Is(err, context.DeadlineExceeded) {
			ar.Timeout = true
		}
		ar.Error = err.Error()
		mergeAttempt(&ar, out)
		return ar, tlsLog
	}

	mergeAttempt(&ar, out)

	// If describe probe is enabled and we got services, probe each one
	if s.cfg.ProbeDescribe && len(ar.Services) > 0 {
		if s.cfg.DescribeSingleConn {
			s.probeDescribeServicesSingleConn(ctx, conn, authority, &ar, which)
		} else {
			s.probeDescribeServices(ctx, dialGroup, target, authority, &ar, which)
		}
	}

	return ar, tlsLog
}

// probeDescribeServices probes DescribeService for each service in the attempt result,
// dialing a fresh connection for every service, skipping internal gRPC services (health,
// reflection) and respecting rate limits.
func (s *Scanner) probeDescribeServices(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, authority string, ar *AttemptResult, which reflectionKind) {
	if ar.ServiceDescriptions == nil {
		ar.ServiceDescriptions = make(map[string]ServiceDescription)
	}

	describeCount := 0
	for _, svcName := range ar.Services {
		// Skip internal gRPC services
		if isInternalGRPCService(svcName) {
			continue
		}

		// Check if we've hit the max limit
		if s.cfg.MaxDescribeServices > 0 && describeCount >= s.cfg.MaxDescribeServices {
			break
		}

		// Check if we still have time
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 100*time.Millisecond {
			break
		}

		// Add delay between requests (except for first)
		if describeCount > 0 && s.cfg.DescribeDelay > 0 {
			select {
			case <-time.After(s.cfg.DescribeDelay):
			case <-ctx.Done():
				return
			}
		}

		// Dial a new connection for this service
		conn2, _, dialErr := dialTarget(ctx, dialGroup, target, s.cfg.UseTLS)
		if dialErr != nil {
			// record error and continue
			sd := ServiceDescription{
				Error: dialErr.Error(),
			}
			ar.ServiceDescriptions[svcName] = sd
			describeCount++
			continue
		}
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn2.SetDeadline(deadline)
		}
		result, grpcStatus, grpcMsg, _, err := probeDescribeService(ctx, conn2, authority, s.cfg.UserAgent, svcName, which)
		conn2.Close()

		sd := ServiceDescription{
			Descriptor:  result.Descriptor,
			GRPCStatus:  grpcStatus,
			GRPCMessage: grpcMsg,
		}
		if err != nil {
			sd.Error = err.Error()
		}

		ar.ServiceDescriptions[svcName] = sd
		describeCount++
	}
}

// isInternalGRPCService checks if a service is an internal gRPC service.
func isInternalGRPCService(serviceName string) bool {
	// Skip gRPC health and reflection services
	return strings.HasPrefix(serviceName, "grpc.health") ||
		strings.HasPrefix(serviceName, "grpc.reflection")
}

// probeDescribeServicesSingleConn reuses the given HTTP/2 connection (which must
// already have completed the client preface/settings exchange) to open a new
// stream for each service.  This avoids dialing additional TCP connections.
func (s *Scanner) probeDescribeServicesSingleConn(ctx context.Context, conn net.Conn, authority string, ar *AttemptResult, which reflectionKind) {
	// create a framer once for the connection, reuse for each stream
	fr := http2.NewFramer(conn, conn)

	if ar.ServiceDescriptions == nil {
		ar.ServiceDescriptions = make(map[string]ServiceDescription)
	}
	describeCount := 0
	// stream IDs must be odd and increasing; 1 was used for ListServices above
	var streamID uint32 = 3

	for _, svcName := range ar.Services {
		if isInternalGRPCService(svcName) {
			continue
		}
		if s.cfg.MaxDescribeServices > 0 && describeCount >= s.cfg.MaxDescribeServices {
			break
		}
		if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < 100*time.Millisecond {
			break
		}
		if describeCount > 0 && s.cfg.DescribeDelay > 0 {
			select {
			case <-time.After(s.cfg.DescribeDelay):
			case <-ctx.Done():
				return
			}
		}

		// build message, headers and send on new stream
		msg, err := buildDescribeServiceMessage(which, svcName)
		if err != nil {
			ar.ServiceDescriptions[svcName] = ServiceDescription{
				Error: fmt.Sprintf("build describe message failed: %v", err),
			}
			describeCount++
			streamID += 2
			continue
		}
		reqHeaders := buildGRPCRequestHeaders(authority, which.Path(), s.cfg.UserAgent)
		hb, err := encodeHeaders(reqHeaders)
		if err != nil {
			ar.ServiceDescriptions[svcName] = ServiceDescription{
				Error: fmt.Sprintf("hpack encode headers failed: %v", err),
			}
			describeCount++
			streamID += 2
			continue
		}
		if err := fr.WriteHeaders(http2.HeadersFrameParam{
			StreamID:      streamID,
			BlockFragment: hb,
			EndHeaders:    true,
			EndStream:     false,
		}); err != nil {
			ar.ServiceDescriptions[svcName] = ServiceDescription{
				Error: fmt.Sprintf("write headers failed: %v", err),
			}
			describeCount++
			streamID += 2
			continue
		}
		if err := fr.WriteData(streamID, true, frameGRPCMessage(msg)); err != nil {
			ar.ServiceDescriptions[svcName] = ServiceDescription{
				Error: fmt.Sprintf("write data failed: %v", err),
			}
			describeCount++
			streamID += 2
			continue
		}

		// read frames for this stream until first message or end
		var (
			respBuf     bytes.Buffer
			gotFirstMsg bool
			sd          ServiceDescription
		)

		for {
			select {
			case <-ctx.Done():
				ar.ServiceDescriptions[svcName] = sd
				return
			default:
			}
			f, err := fr.ReadFrame()
			if err != nil {
				sd.Error = fmt.Sprintf("read frame failed: %v", err)
				break
			}
			switch ff := f.(type) {
			case *http2.HeadersFrame:
				block, endStream, berr := readFullHeaderBlock(fr, ff)
				if berr != nil {
					// ignore
				}
				hdrs := decodeHeaders(block)
				if endStream {
					if st, msg := parseGRPCStatusAndMessage(hdrs); st != nil {
						sd.GRPCStatus = st
						sd.GRPCMessage = msg
					}
					if !gotFirstMsg {
						// no message
						break
					}
					break
				}
			case *http2.DataFrame:
				if ff.StreamID != streamID {
					continue
				}
				if len(ff.Data()) > 0 && !gotFirstMsg {
					respBuf.Write(ff.Data())
					msgBytes, ok := extractFirstGRPCMessage(respBuf.Bytes())
					if ok {
						gotFirstMsg = true
						decoded := decodeDescribeServiceResponse(which, msgBytes, svcName)
						sd.Descriptor = decoded.Descriptor
					}
				}
				if ff.StreamEnded() {
					break
				}
			case *http2.GoAwayFrame:
				// server is closing connection for good
				sd.Error = "received GOAWAY before describe response"
				break
			default:
			}
			if gotFirstMsg {
				// continue reading until trailers (if any);
				// but we can break early to record result
				break
			}
		}

		ar.ServiceDescriptions[svcName] = sd
		describeCount++
		streamID += 2
	}
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
	dst.Services = src.Services
	if src.ServiceDescriptions != nil {
		if dst.ServiceDescriptions == nil {
			dst.ServiceDescriptions = map[string]ServiceDescription{}
		}
		for k, v := range src.ServiceDescriptions {
			dst.ServiceDescriptions[k] = v
		}
	}
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
