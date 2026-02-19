package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	xbuf "github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ---- Types (unchanged) ----

type Handler struct {
	clients  []*protocol.MemoryUser
	fallback *FallbackConfig
}

type MemoryAccount struct {
	Id string
}

func (a *MemoryAccount) Equals(account protocol.Account) bool {
	reflexAccount, ok := account.(*MemoryAccount)
	if !ok {
		return false
	}
	return a.Id == reflexAccount.Id
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &reflex.Account{Id: a.Id}
}

type FallbackConfig struct {
	Dest uint32
}

func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// ---- Registration (unchanged) ----

func init() {
	common.Must(common.RegisterConfig((*reflex.InboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.InboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.InboundConfig) (proxy.Inbound, error) {
	handler := &Handler{
		clients: make([]*protocol.MemoryUser, 0, len(config.Clients)),
	}
	for _, client := range config.Clients {
		handler.clients = append(handler.clients, &protocol.MemoryUser{
			Email:   client.Id,
			Account: &MemoryAccount{Id: client.Id},
		})
	}
	if config.Fallback != nil {
		handler.fallback = &FallbackConfig{Dest: config.Fallback.Dest}
	}
	return handler, nil
}

// ============================================================
// Step 4: Process with Peek-based protocol detection
// ============================================================

// reflexMinPeekSize is enough to see "POST /api/v1/data HTTP/1.1"
// or a future magic number prefix.
const reflexMinPeekSize = 64

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	br := bufio.NewReader(conn)

	// Peek without consuming bytes.
	peeked, err := br.Peek(reflexMinPeekSize)
	if err != nil && len(peeked) == 0 {
		// Connection closed before we got any data.
		return errors.New("reflex inbound: empty connection").Base(err)
	}
	// Note: Peek may return io.EOF with partial data on short connections — that's fine.

	if isReflexHandshake(peeked) {
		return h.handleReflex(ctx, br, conn, dispatcher)
	}
	return h.handleFallback(ctx, br, conn)
}

// ---- Protocol detection ----

// isReflexHandshake returns true if the peeked bytes look like a Reflex handshake.
// Two modes are supported:
//  1. HTTP POST-like (stealth, used in production)
//  2. Magic number prefix (fast path, optional future extension)
func isReflexHandshake(data []byte) bool {
	return isHTTPPostLike(data)
	// To add magic number support later, change to:
	// return isReflexMagic(data) || isHTTPPostLike(data)
}

// isHTTPPostLike checks if data starts with "POST /api/v1/data".
// This is specific enough to avoid false positives from real HTTP traffic.
func isHTTPPostLike(data []byte) bool {
	const prefix = "POST /api/v1/data"
	if len(data) < len(prefix) {
		return false
	}
	return string(data[:len(prefix)]) == prefix
}


// ============================================================
// Step 4: Fallback handler
// ============================================================

// preloadedConn wraps a bufio.Reader over a stat.Connection so that
// peeked bytes are not lost when forwarding to the fallback server.
type preloadedConn struct {
	reader *bufio.Reader
	stat.Connection
}

func (pc *preloadedConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

// handleFallback forwards the connection (including already-peeked bytes)
// to the fallback port configured in InboundConfig.
func (h *Handler) handleFallback(ctx context.Context, br *bufio.Reader, conn stat.Connection) error {
	if h.fallback == nil {
		// No fallback configured: send a plausible HTTP response and close.
		_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return errors.New("reflex inbound: not a Reflex connection and no fallback configured")
	}

	// Dial the fallback server (typically nginx/caddy on localhost).
	target, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: int(h.fallback.Dest),
	})
	if err != nil {
		_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
		return errors.New("reflex inbound: fallback dial failed to 127.0.0.1:", h.fallback.Dest).Base(err)
	}
	defer target.Close()

	// Wrap conn with the bufio.Reader so peeked bytes are included.
	wrapped := &preloadedConn{reader: br, Connection: conn}

	// Bidirectional copy: wrapped ↔ target.
	// We need both directions to finish before returning.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(target, wrapped)
		// Signal the target that we're done writing (triggers EOF on its reader).
		_ = target.CloseWrite()
		done <- err
	}()
	_, _ = io.Copy(wrapped, target)
	<-done
	return nil
}

// ============================================================
// Reflex handshake + session (unchanged from Steps 2 & 3,
// just renamed from the inline Process body to handleReflex)
// ============================================================

func (h *Handler) handleReflex(ctx context.Context, br *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	req, bodyBytes, err := readHTTPRequest(br)
	if err != nil {
		_, _ = conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: not a valid HTTP request").Base(err)
	}
	if req.method != "POST" || req.path != "/api/v1/data" {
		_, _ = conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: unexpected method/path: ", req.method, " ", req.path)
	}

	rawPayload, err := reflex.UnwrapHTTPBody(bodyBytes)
	if err != nil {
		_, _ = conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: bad handshake body").Base(err)
	}
	clientPayload, err := reflex.DecodeClientPayload(rawPayload)
	if err != nil {
		_, _ = conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: bad client payload").Base(err)
	}

	now := time.Now().Unix()
	diff := clientPayload.Timestamp - now
	if diff < 0 {
		diff = -diff
	}
	if diff > 120 {
		_, _ = conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: timestamp too far off: ", diff, "s")
	}

	user, err := h.authenticateUser(clientPayload.UserID)
	if err != nil {
		// Silent fallback — don't reveal auth failure.
		return h.handleFallback(ctx, br, conn)
	}

	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("reflex inbound: keygen failed").Base(err)
	}
	sharedKey, err := reflex.DeriveSharedKey(serverPriv, clientPayload.PublicKey)
	if err != nil {
		return errors.New("reflex inbound: DH failed").Base(err)
	}
	sessionKey, err := reflex.DeriveSessionKey(sharedKey, clientPayload.Nonce)
	if err != nil {
		return errors.New("reflex inbound: KDF failed").Base(err)
	}

	serverPayload := &reflex.ServerPayload{PublicKey: serverPub}
	respBytes, err := reflex.WrapServerHTTP(serverPayload)
	if err != nil {
		return errors.New("reflex inbound: failed to encode server handshake").Base(err)
	}
	if _, err := conn.Write(respBytes); err != nil {
		return errors.New("reflex inbound: failed to send handshake response").Base(err)
	}

	return h.handleSession(ctx, br, conn, dispatcher, sessionKey, user)
}

// ---- Session (unchanged from Step 3) ----

func (h *Handler) handleSession(
	ctx context.Context,
	br *bufio.Reader,
	conn stat.Connection,
	dispatcher routing.Dispatcher,
	sessionKey []byte,
	user *protocol.MemoryUser,
) error {
	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		return errors.New("reflex inbound: failed to create session").Base(err)
	}

	destParsed := false
	var link *transport.Link

	for {
		frame, err := session.ReadFrame(br)
		if err != nil {
			if link != nil {
				_ = common.Interrupt(link.Writer)
			}
			return errors.New("reflex inbound: failed to read frame").Base(err)
		}

		switch frame.Type {
		case reflex.FrameTypeData:
			if !destParsed {
				addrType, addr, port, initialData, err := reflex.DecodeDestination(frame.Payload)
				if err != nil {
					return errors.New("reflex inbound: failed to decode destination").Base(err)
				}
				dest, err := buildDestination(addrType, addr, port)
				if err != nil {
					return errors.New("reflex inbound: invalid destination").Base(err)
				}
				destParsed = true

				link, err = dispatcher.Dispatch(ctx, dest)
				if err != nil {
					return errors.New("reflex inbound: dispatch failed").Base(err)
				}

				go func() {
					defer func() { _ = common.Interrupt(link.Reader) }()
					for {
						mb, err := link.Reader.ReadMultiBuffer()
						if err != nil {
							return
						}
						for _, b := range mb {
							if err := session.WriteFrame(conn, reflex.FrameTypeData, b.Bytes()); err != nil {
								b.Release()
								return
							}
							b.Release()
						}
					}
				}()

				if len(initialData) > 0 {
					b := xbuf.FromBytes(initialData)
					if err := link.Writer.WriteMultiBuffer(xbuf.MultiBuffer{b}); err != nil {
						return errors.New("reflex inbound: failed to write initial data").Base(err)
					}
				}
			} else {
				if link == nil {
					return errors.New("reflex inbound: data frame before destination")
				}
				b := xbuf.FromBytes(frame.Payload)
				if err := link.Writer.WriteMultiBuffer(xbuf.MultiBuffer{b}); err != nil {
					return errors.New("reflex inbound: upstream write failed").Base(err)
				}
			}

		case reflex.FrameTypePadding, reflex.FrameTypeTiming:
			continue

		case reflex.FrameTypeClose:
			if link != nil {
				common.Close(link.Writer)
			}
			_ = session.WriteFrame(conn, reflex.FrameTypeClose, nil)
			return nil

		default:
			return errors.New("reflex inbound: unknown frame type: ", frame.Type)
		}
	}
}

// ---- Authentication (unchanged) ----

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	b := userID
	uuidStr := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	for _, user := range h.clients {
		if user.Account.(*MemoryAccount).Id == uuidStr {
			return user, nil
		}
	}
	return nil, errors.New("user not found: ", uuidStr)
}

// ---- Destination builder (unchanged) ----

func buildDestination(addrType uint8, addr []byte, port uint16) (net.Destination, error) {
	netPort := net.Port(port)
	switch addrType {
	case reflex.AddrTypeIPv4, reflex.AddrTypeIPv6:
		return net.TCPDestination(net.IPAddress(addr), netPort), nil
	case reflex.AddrTypeDomain:
		return net.TCPDestination(net.DomainAddress(string(addr)), netPort), nil
	default:
		return net.Destination{}, errors.New("unknown address type: ", addrType)
	}
}

// ---- Minimal HTTP/1.1 request reader (unchanged) ----

type parsedRequest struct {
	method  string
	path    string
	headers textproto.MIMEHeader
}

func readHTTPRequest(br *bufio.Reader) (*parsedRequest, []byte, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	var method, path, proto_ string
	if _, err := fmt.Sscanf(line, "%s %s %s", &method, &path, &proto_); err != nil {
		return nil, nil, fmt.Errorf("bad request line: %q", line)
	}
	tr := textproto.NewReader(br)
	headers, err := tr.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("bad headers: %w", err)
	}
	clStr := headers.Get("Content-Length")
	if clStr == "" {
		return nil, nil, fmt.Errorf("missing Content-Length")
	}
	cl, err := strconv.Atoi(clStr)
	if err != nil || cl <= 0 {
		return nil, nil, fmt.Errorf("bad Content-Length: %q", clStr)
	}
	body := make([]byte, cl)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, nil, fmt.Errorf("failed to read body: %w", err)
	}
	return &parsedRequest{method: method, path: path, headers: headers}, body, nil
}

// Silence unused imports that are needed in other methods.
var _ = rand.Reader
var _ = json.Marshal
