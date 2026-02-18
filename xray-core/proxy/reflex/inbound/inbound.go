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
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// ---- Types (unchanged from Step 1) ----

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

// ---- Registration (unchanged from Step 1) ----

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

// ---- Step 2: Process with handshake ----

func (h *Handler) Process(ctx context.Context, network net.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	br := bufio.NewReader(conn)

	// Parse the incoming HTTP POST request line + headers.
	req, bodyBytes, err := readHTTPRequest(br)
	if err != nil {
		// Not valid HTTP at all — send fallback and close.
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: not a valid HTTP request").Base(err)
	}

	// Must be POST /api/v1/data
	if req.method != "POST" || req.path != "/api/v1/data" {
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: unexpected method/path: ", req.method, " ", req.path)
	}

	// Decode base64 → binary ClientPayload.
	rawPayload, err := reflex.UnwrapHTTPBody(bodyBytes)
	if err != nil {
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: bad handshake body").Base(err)
	}

	clientPayload, err := reflex.DecodeClientPayload(rawPayload)
	if err != nil {
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: bad client payload").Base(err)
	}

	// Replay protection: reject if timestamp is more than 120 seconds off.
	now := time.Now().Unix()
	diff := clientPayload.Timestamp - now
	if diff < 0 {
		diff = -diff
	}
	if diff > 120 {
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: timestamp too far off: ", diff, "s")
	}

	// Authenticate user by UUID bytes.
	user, err := h.authenticateUser(clientPayload.UserID)
	if err != nil {
		// User not found — silent fallback (don't reveal why).
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: auth failed").Base(err)
	}

	// Generate server ephemeral key pair.
	serverPriv, serverPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("reflex inbound: keygen failed").Base(err)
	}

	// DH + session key derivation.
	sharedKey, err := reflex.DeriveSharedKey(serverPriv, clientPayload.PublicKey)
	if err != nil {
		return errors.New("reflex inbound: DH failed").Base(err)
	}
	sessionKey, err := reflex.DeriveSessionKey(sharedKey, clientPayload.Nonce)
	if err != nil {
		return errors.New("reflex inbound: KDF failed").Base(err)
	}

	// Send HTTP 200 with server's public key.
	serverPayload := &reflex.ServerPayload{PublicKey: serverPub}
	respBytes, err := reflex.WrapServerHTTP(serverPayload)
	if err != nil {
		return errors.New("reflex inbound: failed to encode server handshake").Base(err)
	}
	if _, err := conn.Write(respBytes); err != nil {
		return errors.New("reflex inbound: failed to send handshake response").Base(err)
	}

	// Handshake done — hand off to session handler (Step 3 will use sessionKey).
	_ = user
	_ = sessionKey
	return h.handleSession(ctx, br, conn, dispatcher)
}

// ---- Authentication ----

func (h *Handler) authenticateUser(userID [16]byte) (*protocol.MemoryUser, error) {
	// Convert raw bytes to UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
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

// ---- Fallback ----

func (h *Handler) handleFallback(ctx context.Context, conn stat.Connection) error {
	if h.fallback == nil {
		conn.Write([]byte(reflex.FallbackResponse))
		return nil
	}
	// Forward to fallback port (simple TCP dial).
	dest := net.TCPDestination(net.LocalHostIP, net.Port(h.fallback.Dest))
	fconn, err := net.Dial("tcp", dest.NetAddr())
	if err != nil {
		conn.Write([]byte(reflex.FallbackResponse))
		return errors.New("reflex inbound: fallback dial failed").Base(err)
	}
	defer fconn.Close()
	go io.Copy(fconn, conn)
	io.Copy(conn, fconn)
	return nil
}

// ---- Session stub (filled in Step 3) ----

func (h *Handler) handleSession(ctx context.Context, br *bufio.Reader, conn stat.Connection, dispatcher routing.Dispatcher) error {
	// Step 3 will add encryption + traffic forwarding here.
	return nil
}

// ---- Minimal HTTP/1.1 request reader ----

type parsedRequest struct {
	method  string
	path    string
	headers textproto.MIMEHeader
}

func readHTTPRequest(br *bufio.Reader) (*parsedRequest, []byte, error) {
	// Read request line.
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, nil, err
	}
	var method, path, proto_ string
	if _, err := fmt.Sscanf(line, "%s %s %s", &method, &path, &proto_); err != nil {
		return nil, nil, fmt.Errorf("bad request line: %q", line)
	}

	// Read headers using net/textproto.
	tr := textproto.NewReader(br)
	headers, err := tr.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, nil, fmt.Errorf("bad headers: %w", err)
	}

	// Read body (Content-Length bytes).
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

// Silence unused import if rand isn't used elsewhere yet.
var _ = rand.Reader
var _ = json.Marshal
