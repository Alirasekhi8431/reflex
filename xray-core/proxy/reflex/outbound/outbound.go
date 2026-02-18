package outbound

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

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
)

type Handler struct {
	server *protocol.ServerSpec
	pm     policy.Manager
}

func init() {
	common.Must(common.RegisterConfig((*reflex.OutboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return New(ctx, config.(*reflex.OutboundConfig))
	}))
}

func New(ctx context.Context, config *reflex.OutboundConfig) (*Handler, error) {
	dest := net.TCPDestination(net.DomainAddress(config.Address), net.Port(config.Port))

	user := &protocol.MemoryUser{
		Email: "",
		// For Reflex we don’t use account here yet.
	}

	spec := &protocol.ServerSpec{
		Destination: dest,
		User:        user,
	}

	v := core.MustFromContext(ctx)

	return &Handler{
		server: spec,
		pm:     v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

func readHTTPResponse(br *bufio.Reader) ([]byte, error) {
	// Read status line.
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var proto_, status string
	var code int
	fmt.Sscanf(line, "%s %d %s", &proto_, &code, &status)
	if code != 200 {
		return nil, fmt.Errorf("reflex: server returned HTTP %d", code)
	}

	// Read headers.
	tr := textproto.NewReader(br)
	headers, err := tr.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("reflex: bad response headers: %w", err)
	}

	// Read body.
	clStr := headers.Get("Content-Length")
	cl, err := strconv.Atoi(clStr)
	if err != nil || cl <= 0 {
		return nil, fmt.Errorf("reflex: bad Content-Length in response: %q", clStr)
	}
	body := make([]byte, cl)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, fmt.Errorf("reflex: failed to read response body: %w", err)
	}

	return reflex.UnwrapHTTPBody(body)
}

var _ = json.Marshal // silence unused import

// Process implements proxy.Outbound.Process.
func (h *Handler) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	conn, err := dialer.Dial(ctx, h.server.Destination)
	if err != nil {
		return errors.New("reflex outbound: dial failed").Base(err)
	}
	defer conn.Close()

	// --- Step 2: Send client handshake ---

	// Generate ephemeral key pair.
	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		return errors.New("reflex outbound: keygen failed").Base(err)
	}

	// Build ClientPayload.
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix(),
	}
	// Fill UserID from the handler's configured UUID.
	copy(payload.UserID[:], uuidStringToBytes(h.server.User.Email))
	// Random nonce.
	if _, err := io.ReadFull(rand.Reader, payload.Nonce[:]); err != nil {
		return errors.New("reflex outbound: nonce generation failed").Base(err)
	}

	// Wrap in HTTP POST and send.
	reqBytes, err := reflex.WrapClientHTTP(payload, h.server.Destination.Address.String())
	if err != nil {
		return errors.New("reflex outbound: failed to encode handshake").Base(err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		return errors.New("reflex outbound: failed to send handshake").Base(err)
	}

	// --- Read server HTTP 200 response ---
	br := bufio.NewReader(conn)
	serverPayloadBytes, err := readHTTPResponse(br)
	if err != nil {
		return errors.New("reflex outbound: failed to read server handshake").Base(err)
	}

	// Decode server public key.
	serverPayload, err := reflex.DecodeServerPayload(serverPayloadBytes)
	if err != nil {
		return errors.New("reflex outbound: bad server payload").Base(err)
	}

	// DH + session key.
	sharedKey, err := reflex.DeriveSharedKey(clientPriv, serverPayload.PublicKey)
	if err != nil {
		return errors.New("reflex outbound: DH failed").Base(err)
	}
	sessionKey, err := reflex.DeriveSessionKey(sharedKey, payload.Nonce)
	if err != nil {
		return errors.New("reflex outbound: KDF failed").Base(err)
	}

	// Handshake done — hand off to session (Step 3 will use sessionKey).
	_ = sessionKey
	return pipeTraffic(conn, link)
}

// pipeTraffic is a simple TCP bidirectional copy (placeholder until Step 3).
func pipeTraffic(conn net.Conn, link *transport.Link) error {
	uplinkDone := make(chan error, 1)
	go func() {
		uplinkDone <- buf.Copy(link.Reader, buf.NewWriter(conn), nil)
		common.Interrupt(buf.NewWriter(conn))
	}()
	downErr := buf.Copy(buf.NewReader(conn), link.Writer, nil)
	upErr := <-uplinkDone
	if downErr != nil {
		return downErr
	}
	return upErr
}

// uuidStringToBytes converts "xxxxxxxx-xxxx-..." string to 16 bytes.
// Returns zeroes if parsing fails.
func uuidStringToBytes(s string) []byte {
	out := make([]byte, 16)
	hex := []byte{}
	for _, c := range []byte(s) {
		if c != '-' {
			hex = append(hex, c)
		}
	}
	if len(hex) != 32 {
		return out
	}
	for i := 0; i < 16; i++ {
		hi := hexVal(hex[i*2])
		lo := hexVal(hex[i*2+1])
		out[i] = hi<<4 | lo
	}
	return out
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}
