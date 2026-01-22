package grpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/zmap/zgrab2"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/protobuf/proto"

	refv1 "google.golang.org/grpc/reflection/grpc_reflection_v1"
	refa "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
)

type reflectionKind int

const (
	reflectionV1 reflectionKind = iota
	reflectionV1Alpha
)

func (k reflectionKind) String() string {
	switch k {
	case reflectionV1:
		return "v1"
	case reflectionV1Alpha:
		return "v1alpha"
	default:
		return "unknown"
	}
}

func (k reflectionKind) Path() string {
	switch k {
	case reflectionV1:
		return "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
	case reflectionV1Alpha:
		return "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
	default:
		return "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
	}
}

func dialTarget(ctx context.Context, dialGroup *zgrab2.DialerGroup, target *zgrab2.ScanTarget, useTLS bool) (net.Conn, *zgrab2.TLSLog, error) {
	addr := net.JoinHostPort(target.IP.String(), strconv.Itoa(int(target.Port)))

	if !useTLS {
		conn, err := dialGroup.L4Dialer(target)(ctx, "tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("plaintext dial failed: %w", err)
		}
		return conn, nil, nil
	}

	// TLS
	connTLS, err := dialGroup.GetTLSDialer(ctx, target)("tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("TLS dial failed: %w", err)
	}

	var log *zgrab2.TLSLog
	log = connTLS.GetLog()
	// Some tls.Conn types have ConnectionState() with NegotiatedProtocol, but we avoid type assertions here.
	return connTLS, log, nil
}

// probeReflectionOnce sends one ListServices request, reads first response if available,
// otherwise records headers/trailers and cancels the stream.
func probeReflectionOnce(ctx context.Context, conn net.Conn, authority, userAgent string, which reflectionKind) (AttemptResult, error) {

	fr := http2.NewFramer(conn, conn)

	if err := writeClientPrefaceAndSettings(conn, fr); err != nil {
		return AttemptResult{}, fmt.Errorf("http2 preface/settings failed: %w", err)
	}
	// Send client preface + initial settings

	// Read server settings and ACK them (best-effort)
	_ = readAndAckServerSettings(fr)

	streamID := uint32(1)

	// Build and send request HEADERS
	reqHeaders := buildGRPCRequestHeaders(authority, which.Path(), userAgent)
	hb, err := encodeHeaders(reqHeaders)
	if err != nil {
		return AttemptResult{}, fmt.Errorf("hpack encode headers failed: %w", err)
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      streamID,
		BlockFragment: hb,
		EndHeaders:    true,
		EndStream:     false,
	}); err != nil {
		return AttemptResult{}, fmt.Errorf("write headers failed: %w", err)
	}

	// Build reflection request payload (protobuf + gRPC 5-byte message prefix)
	msg, err := buildListServicesMessage(which)
	if err != nil {
		return AttemptResult{}, err
	}
	grpcData := frameGRPCMessage(msg)

	// Send one DATA frame and half-close (EndStream=true)
	if err := fr.WriteData(streamID, true, grpcData); err != nil {
		return AttemptResult{}, fmt.Errorf("write data failed: %w", err)
	}

	// Read frames until:
	// - first reflection response message is decoded, OR
	// - we get trailers with END_STREAM, OR
	// - ctx deadline hits
	out := AttemptResult{
		Path: which.Path(),
	}

	var (
		respBuf       bytes.Buffer
		gotFirstMsg   bool
		firstMsgBytes []byte
	)

	for {
		// Respect context deadline (conn has a deadline set by caller, but check anyway)
		select {
		case <-ctx.Done():
			// Cancel stream (best-effort) and return what we have.
			_ = fr.WriteRSTStream(streamID, http2.ErrCodeCancel)
			out.Timeout = true
			return out, ctx.Err()
		default:
		}

		f, err := fr.ReadFrame()
		if err != nil {
			// Connection-level read error; return what we have.
			// Some targets will close abruptly; keep partial headers/trailers.
			return out, fmt.Errorf("read frame failed: %w", err)
		}

		switch ff := f.(type) {
		case *http2.HeadersFrame:
			block, endStream, berr := readFullHeaderBlock(fr, ff)
			if berr != nil {
				out.Error = berr.Error()
				continue
			}
			hdrs := decodeHeaders(block)

			// HEADERS without END_STREAM are response headers, HEADERS with END_STREAM are trailers.

			// If the server returns "content-type: application/grpc" we'll see it here.
			if !endStream {
				out.Headers = hdrs
				out.HTTPStatus = parseHTTPStatus(hdrs)

			}

			if endStream {
				// END_STREAM on headers means stream is done (trailers-only or trailers end)
				if !gotFirstMsg {
					out.Trailers = hdrs
					st, msg := parseGRPCStatusAndMessage(hdrs)
					out.GRPCStatus = st
					out.GRPCMessage = msg

					// no message ever arrived, END_STREAM means we are done
					return out, nil
				}
				// the headers that came with the END_STREAM are trailers
				out.Trailers = hdrs
				st, msg := parseGRPCStatusAndMessage(hdrs)
				out.GRPCStatus = st
				out.GRPCMessage = msg

				return out, nil
			}

		case *http2.DataFrame:
			if ff.StreamID != streamID {
				continue
			}
			if len(ff.Data()) > 0 && !gotFirstMsg {
				respBuf.Write(ff.Data())
				// Try to extract first gRPC message from buffer
				msgBytes, ok := extractFirstGRPCMessage(respBuf.Bytes())
				if ok {
					gotFirstMsg = true
					firstMsgBytes = msgBytes
					out.ReflectionResponseRawBase64 = base64.StdEncoding.EncodeToString(firstMsgBytes)

					// Best-effort decode services list
					svcs := decodeListServicesResponse(which, firstMsgBytes)
					if len(svcs) > 0 {
						out.Services = svcs
					}

					// We can return early, but you asked to keep whatever trailers you got.
					// So: keep reading a bit for trailers until END_STREAM or ctx deadline.
					// If the server stalls, ctx deadline will stop us.
				}
			}
			if ff.StreamEnded() {
				// Stream ended without trailers? Return what we have.
				if !gotFirstMsg {
					return out, nil
				}
				return out, nil
			}

		case *http2.RSTStreamFrame:
			if ff.StreamID == streamID {
				// Server reset the stream. Return what we have.
				if !gotFirstMsg {
					return out, fmt.Errorf("stream reset: %v", ff.ErrCode)
				}
				return out, nil
			}

		case *http2.GoAwayFrame:
			// Connection is shutting down. Return what we have.
			if gotFirstMsg {
				return out, nil
			}
			return out, errors.New("received GOAWAY before response")

		default:
			// Ignore other frames (SETTINGS, WINDOW_UPDATE, PING, etc.)
		}

		// If we already got the first response message, keep looping to possibly capture trailers,
		// but don't do it forever; ctx deadline will cap it.
		_ = firstMsgBytes
	}
}

func writeClientPrefaceAndSettings(conn net.Conn, fr *http2.Framer) error {
	// HTTP/2 connection preface MUST be raw bytes on the wire
	if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
		return err
	}

	// Then send SETTINGS as an HTTP/2 frame
	if err := fr.WriteSettings(); err != nil {
		return err
	}

	// Optional: increase connection window
	_ = fr.WriteWindowUpdate(0, 1<<20)
	return nil
}

func readAndAckServerSettings(fr *http2.Framer) error {
	// Best-effort: read until SETTINGS then ACK once.
	for i := 0; i < 4; i++ { // don't loop forever
		f, err := fr.ReadFrame()
		if err != nil {
			return err
		}
		if sf, ok := f.(*http2.SettingsFrame); ok {
			if sf.IsAck() {
				return nil
			}
			return fr.WriteSettingsAck()
		}
	}
	return nil
}

func buildGRPCRequestHeaders(authority, path, userAgent string) []hpack.HeaderField {
	// Required pseudo headers for HTTP/2 request
	h := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"}, // ok even for TLS; servers usually ignore; if you want, set "https" in caller logic
		{Name: ":path", Value: path},
		{Name: ":authority", Value: authority},
		// gRPC headers
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
		{Name: "user-agent", Value: userAgent},
	}
	return h
}

func encodeHeaders(hdrs []hpack.HeaderField) ([]byte, error) {
	var buf bytes.Buffer
	enc := hpack.NewEncoder(&buf)
	for _, hf := range hdrs {
		if err := enc.WriteField(hf); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func readFullHeaderBlock(fr *http2.Framer, hf *http2.HeadersFrame) ([]byte, bool, error) {
	var block bytes.Buffer
	block.Write(hf.HeaderBlockFragment())

	endStream := hf.StreamEnded()

	// If header block spans CONTINUATION frames, read them
	for !hf.HeadersEnded() {
		f, err := fr.ReadFrame()
		if err != nil {
			return nil, endStream, err
		}
		cf, ok := f.(*http2.ContinuationFrame)
		if !ok {
			return nil, endStream, fmt.Errorf("expected CONTINUATION, got %T", f)
		}
		block.Write(cf.HeaderBlockFragment())
		if cf.HeadersEnded() {
			break
		}
	}
	return block.Bytes(), endStream, nil
}

func decodeHeaders(block []byte) map[string][]string {
	out := map[string][]string{}
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		name := strings.ToLower(f.Name)
		out[name] = append(out[name], f.Value)
	})
	_, _ = dec.Write(block)
	return out
}

func parseHTTPStatus(h map[string][]string) int {
	if vs, ok := h[":status"]; ok && len(vs) > 0 {
		if n, err := strconv.Atoi(vs[0]); err == nil {
			return n
		}
	}
	return 0
}

func parseGRPCStatusAndMessage(h map[string][]string) (*int32, string) {
	var (
		stPtr *int32
		msg   string
	)
	if vs, ok := h["grpc-status"]; ok && len(vs) > 0 {
		if n, err := strconv.Atoi(vs[0]); err == nil {
			tmp := int32(n)
			stPtr = &tmp
		}
	}
	if vs, ok := h["grpc-message"]; ok && len(vs) > 0 {
		msg = vs[0]
	}
	return stPtr, msg
}

func buildListServicesMessage(which reflectionKind) ([]byte, error) {
	switch which {
	case reflectionV1:
		req := &refv1.ServerReflectionRequest{
			MessageRequest: &refv1.ServerReflectionRequest_ListServices{
				ListServices: "*",
			},
		}
		return proto.Marshal(req)
	case reflectionV1Alpha:
		req := &refa.ServerReflectionRequest{
			MessageRequest: &refa.ServerReflectionRequest_ListServices{
				ListServices: "*",
			},
		}
		return proto.Marshal(req)
	default:
		return nil, errors.New("unknown reflection kind")
	}
}

// gRPC wire format: 1 byte compression flag + 4 byte big-endian length + protobuf bytes
func frameGRPCMessage(pb []byte) []byte {
	out := make([]byte, 5+len(pb))
	out[0] = 0 // not compressed
	// length
	n := uint32(len(pb))
	out[1] = byte(n >> 24)
	out[2] = byte(n >> 16)
	out[3] = byte(n >> 8)
	out[4] = byte(n)
	copy(out[5:], pb)
	return out
}

func extractFirstGRPCMessage(buf []byte) ([]byte, bool) {
	if len(buf) < 5 {
		return nil, false
	}
	// buf[0] compression flag (ignore)
	n := uint32(buf[1])<<24 | uint32(buf[2])<<16 | uint32(buf[3])<<8 | uint32(buf[4])
	if uint32(len(buf)) < 5+n {
		return nil, false
	}
	msg := make([]byte, n)
	copy(msg, buf[5:5+n])
	return msg, true
}

func decodeListServicesResponse(which reflectionKind, msg []byte) []string {
	switch which {
	case reflectionV1:
		var resp refv1.ServerReflectionResponse
		if err := proto.Unmarshal(msg, &resp); err != nil {
			return nil
		}
		ls := resp.GetListServicesResponse()
		if ls == nil {
			return nil
		}
		out := make([]string, 0, len(ls.Service))
		for _, s := range ls.Service {
			out = append(out, s.Name)
		}
		return out

	case reflectionV1Alpha:
		var resp refa.ServerReflectionResponse
		if err := proto.Unmarshal(msg, &resp); err != nil {
			return nil
		}
		ls := resp.GetListServicesResponse()
		if ls == nil {
			return nil
		}
		out := make([]string, 0, len(ls.Service))
		for _, s := range ls.Service {
			out = append(out, s.Name)
		}
		return out

	default:
		return nil
	}
}
