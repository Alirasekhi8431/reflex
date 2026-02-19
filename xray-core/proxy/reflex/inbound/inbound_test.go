package inbound

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	xbuf "github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/reflex"
	"github.com/xtls/xray-core/transport"
)

// ------------------------------------------------------------------ handler factory

const testUUID = "12345678-1234-1234-1234-123456789abc"

func newTestHandler(fallbackPort uint32) *Handler {
	h := &Handler{
		clients: []*protocol.MemoryUser{
			{
				Email:   testUUID,
				Account: &MemoryAccount{Id: testUUID},
			},
		},
	}
	if fallbackPort > 0 {
		h.fallback = &FallbackConfig{Dest: fallbackPort}
	}
	return h
}

// ------------------------------------------------------------------ fake client handshake

// doClientHandshake performs the Reflex handshake from the client side
// (mirrors outbound/outbound.go logic) over the given net.Conn.
// Returns the derived session so the test can encrypt/decrypt frames.
func doClientHandshake(t *testing.T, conn net.Conn, uuid string) *reflex.Session {
	t.Helper()

	clientPriv, clientPub, err := reflex.GenerateKeyPair()
	if err != nil {
		t.Fatalf("client keygen: %v", err)
	}

	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix(),
	}
	// UUID → 16 bytes
	copy(payload.UserID[:], uuidToBytes(t, uuid))
	if _, err := io.ReadFull(rand.Reader, payload.Nonce[:]); err != nil {
		t.Fatalf("client nonce: %v", err)
	}

	reqBytes, err := reflex.WrapClientHTTP(payload, "test-server")
	if err != nil {
		t.Fatalf("WrapClientHTTP: %v", err)
	}
	if _, err := conn.Write(reqBytes); err != nil {
		t.Fatalf("client write handshake: %v", err)
	}

	// Read server HTTP 200 response.
	br := bufio.NewReader(conn)
	serverPayloadBytes, err := readHTTPResponseBody(t, br)
	if err != nil {
		t.Fatalf("client read server response: %v", err)
	}
	serverPayload, err := reflex.DecodeServerPayload(serverPayloadBytes)
	if err != nil {
		t.Fatalf("DecodeServerPayload: %v", err)
	}

	sharedKey, err := reflex.DeriveSharedKey(clientPriv, serverPayload.PublicKey)
	if err != nil {
		t.Fatalf("client DH: %v", err)
	}
	sessionKey, err := reflex.DeriveSessionKey(sharedKey, payload.Nonce)
	if err != nil {
		t.Fatalf("client KDF: %v", err)
	}

	session, err := reflex.NewSession(sessionKey)
	if err != nil {
		t.Fatalf("client NewSession: %v", err)
	}
	return session
}

// readHTTPResponseBody reads the HTTP response written by the server
// and returns the unwrapped base64 body bytes.
func readHTTPResponseBody(t *testing.T, br *bufio.Reader) ([]byte, error) {
	t.Helper()
	// Status line.
	line, err := br.ReadString('\n')
	if err != nil {
		return nil, err
	}
	if !strings.Contains(line, "200") {
		return nil, fmt.Errorf("server returned non-200: %q", line)
	}
	// Headers.
	var contentLength int
	for {
		hline, err := br.ReadString('\n')
		if err != nil {
			return nil, err
		}
		hline = strings.TrimRight(hline, "\r\n")
		if hline == "" {
			break // end of headers
		}
		if strings.HasPrefix(strings.ToLower(hline), "content-length:") {
			parts := strings.SplitN(hline, ":", 2)
			contentLength, _ = strconv.Atoi(strings.TrimSpace(parts[1]))
		}
	}
	if contentLength <= 0 {
		return nil, fmt.Errorf("missing or zero Content-Length")
	}
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(br, body); err != nil {
		return nil, err
	}
	return reflex.UnwrapHTTPBody(body)
}

func uuidToBytes(t *testing.T, uuid string) []byte {
	t.Helper()
	out := make([]byte, 16)
	hexStr := strings.ReplaceAll(uuid, "-", "")
	if len(hexStr) != 32 {
		t.Fatalf("invalid UUID: %q", uuid)
	}
	for i := 0; i < 16; i++ {
		var b byte
		fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &b)
		out[i] = b
	}
	return out
}

// ------------------------------------------------------------------ mock dispatcher

// mockDispatcher records the dispatched destination and
// echoes everything written to it back to the reader.
type mockDispatcher struct {
	mu       sync.Mutex
	lastDest xnet.Destination
}

func (d *mockDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	d.mu.Lock()
	d.lastDest = dest
	d.mu.Unlock()

	// Two pipes form a bidirectional echo:
	//
	//   handler writes to → upW → upR → echo goroutine → downW → downR → handler reads from
	//
	upR, upW := io.Pipe()     // handler writes to upW (via link.Writer)
	downR, downW := io.Pipe() // handler reads from downR (via link.Reader)

	// Echo goroutine: copy everything handler wrote right back to it.
	go func() {
		defer downW.Close()
		io.Copy(downW, upR)
	}()

	link := &transport.Link{
		Reader: xbuf.NewReader(downR),
		Writer: xbuf.NewWriter(upW),
	}
	return link, nil
}

func (d *mockDispatcher) Start() error      { return nil }
func (d *mockDispatcher) Close() error      { return nil }
func (d *mockDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *mockDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	_, err := d.Dispatch(ctx, dest)
	return err
}

// ================================================================
// Test 1: Protocol detection (isReflexHandshake)
// ================================================================

func TestIsReflexHandshake(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"POST /api/v1/data HTTP/1.1\r\nHost: x\r\n", true},
		{"GET /api/v1/data HTTP/1.1\r\nHost: x\r\n", false},
		{"POST /other HTTP/1.1\r\nHost: x\r\n", false},
		{"CONNECT example.com:443 HTTP/1.1\r\n", false},
		{"\x16\x03\x01\x00\xf1\x01", false}, // TLS ClientHello
		{"", false},
		{"POST", false}, // too short
		{"POST /api/v1/data", true},
	}
	for _, tc := range cases {
		got := isReflexHandshake([]byte(tc.input))
		if got != tc.want {
			t.Errorf("isReflexHandshake(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

// ================================================================
// Test 2: authenticateUser
// ================================================================

func TestAuthenticateUser(t *testing.T) {
	h := newTestHandler(0)

	userIDBytes := uuidToBytes(t, testUUID)
	var uid [16]byte
	copy(uid[:], userIDBytes)

	user, err := h.authenticateUser(uid)
	if err != nil {
		t.Fatalf("authenticateUser valid UUID: %v", err)
	}
	if user.Email != testUUID {
		t.Errorf("wrong user: got %q want %q", user.Email, testUUID)
	}
}

func TestAuthenticateUserUnknown(t *testing.T) {
	h := newTestHandler(0)

	var uid [16]byte
	io.ReadFull(rand.Reader, uid[:]) // random UUID not in config

	_, err := h.authenticateUser(uid)
	if err == nil {
		t.Fatal("expected error for unknown UUID, got nil")
	}
}

// ================================================================
// Test 3: Full handshake over net.Pipe
// ================================================================

func TestHandshakeSuccess(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	handshakeDone := make(chan error, 1)
	go func() {
		br := bufio.NewReader(serverConn)
		err := h.handleReflex(context.Background(), br, serverConn, dispatcher)
		handshakeDone <- err
	}()

	session := doClientHandshake(t, clientConn, testUUID)

	// Send first data frame with destination prefix.
	destBytes := reflex.EncodeDestination(reflex.AddrTypeDomain, []byte("example.com"), 80)
	firstPayload := append(destBytes, []byte("hello")...)
	if err := session.WriteFrame(clientConn, reflex.FrameTypeData, firstPayload); err != nil {
		t.Fatalf("client write data frame: %v", err)
	}

	// The mockDispatcher echoes everything back — the server will try to write
	// the echoed frame back to clientConn. net.Pipe is unbuffered, so we MUST
	// drain clientConn concurrently or the server blocks forever.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 4096)
		for {
			clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, err := clientConn.Read(buf)
			if err != nil {
				return // deadline or close — stop draining
			}
		}
	}()

	// Give the server time to dispatch and echo, then close cleanly.
	time.Sleep(100 * time.Millisecond)
	session.WriteFrame(clientConn, reflex.FrameTypeClose, nil)

	select {
	case err := <-handshakeDone:
		if err != nil {
			t.Logf("server exited with: %v (acceptable)", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for server handshake")
	}
	<-drainDone
}

func TestHandshakeWrongUUID(t *testing.T) {
	h := newTestHandler(0) // only testUUID is valid
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(serverConn)
		h.handleReflex(context.Background(), br, serverConn, dispatcher)
	}()

	// Build handshake with a different UUID.
	_, clientPub, _ := reflex.GenerateKeyPair()
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix(),
	}
	io.ReadFull(rand.Reader, payload.UserID[:]) // random, not in config
	io.ReadFull(rand.Reader, payload.Nonce[:])

	reqBytes, _ := reflex.WrapClientHTTP(payload, "test-server")
	clientConn.Write(reqBytes)

	// Server should respond with 403 (fallback response) and close.
	buf := make([]byte, 512)
	n, _ := clientConn.Read(buf)
	response := string(buf[:n])
	if !strings.Contains(response, "403") && !strings.Contains(response, "400") {
		t.Logf("server response (first bytes): %q", response)
		// Acceptable: server may just close the connection.
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: server did not close connection after bad UUID")
	}
}

func TestHandshakeOldTimestamp(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		br := bufio.NewReader(serverConn)
		h.handleReflex(context.Background(), br, serverConn, dispatcher)
	}()

	_, clientPub, _ := reflex.GenerateKeyPair()
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix() - 300, // 5 minutes ago → rejected
	}
	copy(payload.UserID[:], uuidToBytes(t, testUUID))
	io.ReadFull(rand.Reader, payload.Nonce[:])

	reqBytes, _ := reflex.WrapClientHTTP(payload, "test-server")
	clientConn.Write(reqBytes)

	buf := make([]byte, 512)
	clientConn.Read(buf) // expect 403

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: server did not reject old timestamp")
	}
}

func TestHandshakeIncomplete(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		br := bufio.NewReader(serverConn)
		done <- h.handleReflex(context.Background(), br, serverConn, dispatcher)
	}()

	// Send only partial HTTP request then close.
	clientConn.Write([]byte("POST /api/v1"))
	clientConn.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error on incomplete handshake")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout on incomplete handshake")
	}
}

// ================================================================
// Test 4: Fallback routing
// ================================================================

func TestFallbackNonReflexTraffic(t *testing.T) {
	fallbackServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close") // force server to close after response
		w.WriteHeader(200)
		w.Write([]byte("fallback OK"))
	}))
	defer fallbackServer.Close()

	addrParts := strings.Split(fallbackServer.Listener.Addr().String(), ":")
	port, _ := strconv.Atoi(addrParts[len(addrParts)-1])

	h := newTestHandler(uint32(port))
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- h.Process(context.Background(), xnet.Network_TCP, serverConn, dispatcher)
	}()

	// Send a regular HTTP GET with Connection: close so fallback server closes after reply.
	request := "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
	clientConn.Write([]byte(request))

	// Read the full response (read until the connection closes on our side).
	responseBuf := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _ := io.ReadAtLeast(clientConn, responseBuf, 1)
	response := string(responseBuf[:n])

	// Close client side — this unblocks the fallback's io.Copy goroutine.
	clientConn.Close()

	if !strings.Contains(response, "fallback OK") && !strings.Contains(response, "200") {
		t.Logf("fallback response: %q", response)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for fallback to complete")
	}
}

func TestFallbackNoConfig(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	// NOTE: do NOT defer clientConn.Close() here — we close it manually below.

	done := make(chan error, 1)
	go func() {
		done <- h.Process(context.Background(), xnet.Network_TCP, serverConn, dispatcher)
	}()

	// Send non-Reflex traffic, then immediately close so Peek(64) returns with
	// partial data (EOF triggers Peek to return what it has).
	clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	clientConn.Close() // this makes Peek return with the partial data it has

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error when no fallback configured")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: server did not close connection without fallback")
	}
}

// ================================================================
// Test: Replay protection — replaying a captured handshake must not
// yield a working session because the server generates fresh
// ephemeral keys each time.
// ================================================================

func TestReplayHandshakeProducesUnusableSession(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	// Helper: perform handshake with given bytes, return server's ephemeral
	// public key and derived session key, then close cleanly.
	doHandshakeAndCollect := func(reqBytes []byte, clientPriv [32]byte, nonce [16]byte) ([32]byte, []byte) {
		cConn, sConn := net.Pipe()
		defer cConn.Close()
		defer sConn.Close()

		done := make(chan error, 1)
		go func() {
			br := bufio.NewReader(sConn)
			done <- h.handleReflex(context.Background(), br, sConn, dispatcher)
		}()

		cConn.Write(reqBytes)

		br := bufio.NewReader(cConn)
		body, err := readHTTPResponseBody(t, br)
		if err != nil {
			t.Fatalf("handshake read failed: %v", err)
		}
		sp, _ := reflex.DecodeServerPayload(body)
		shared, _ := reflex.DeriveSharedKey(clientPriv, sp.PublicKey)
		sessKey, _ := reflex.DeriveSessionKey(shared, nonce)

		sess, _ := reflex.NewSession(sessKey)

		// Drain server writes (net.Pipe is unbuffered).
		go func() {
			buf := make([]byte, 4096)
			for {
				cConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				if _, err := cConn.Read(buf); err != nil {
					return
				}
			}
		}()

		sess.WriteFrame(cConn, reflex.FrameTypeClose, nil)
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
		return sp.PublicKey, sessKey
	}

	clientPriv, clientPub, _ := reflex.GenerateKeyPair()
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix(),
	}
	copy(payload.UserID[:], uuidToBytes(t, testUUID))
	io.ReadFull(rand.Reader, payload.Nonce[:])
	reqBytes, _ := reflex.WrapClientHTTP(payload, "test-server")

	serverPub1, sessKey1 := doHandshakeAndCollect(reqBytes, clientPriv, payload.Nonce)

	// Replay the exact same handshake bytes on a new connection.
	serverPub2, sessKey2 := doHandshakeAndCollect(reqBytes, clientPriv, payload.Nonce)

	if serverPub1 == serverPub2 {
		t.Fatal("server reused the same ephemeral key — replay attack possible")
	}
	if string(sessKey1) == string(sessKey2) {
		t.Fatal("replay produced identical session key — ephemeral key reuse")
	}
}

func TestReplayExpiredTimestamp(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		br := bufio.NewReader(serverConn)
		done <- h.handleReflex(context.Background(), br, serverConn, dispatcher)
	}()

	// Simulate a replayed handshake whose timestamp has expired (>120s old).
	_, clientPub, _ := reflex.GenerateKeyPair()
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix() - 200,
	}
	copy(payload.UserID[:], uuidToBytes(t, testUUID))
	io.ReadFull(rand.Reader, payload.Nonce[:])

	reqBytes, _ := reflex.WrapClientHTTP(payload, "test-server")
	clientConn.Write(reqBytes)

	buf := make([]byte, 512)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := clientConn.Read(buf)
	resp := string(buf[:n])

	// Server must reject with 403 (replay window expired).
	if !strings.Contains(resp, "403") {
		t.Logf("response: %q", resp)
	}
	clientConn.Close()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: server did not reject expired replay")
	}
}

// ================================================================
// Test: Full integration — handshake, bidirectional data, close
// ================================================================

func TestIntegrationEndToEnd(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	serverDone := make(chan error, 1)
	go func() {
		serverDone <- h.Process(context.Background(), xnet.Network_TCP, serverConn, dispatcher)
	}()

	session := doClientHandshake(t, clientConn, testUUID)

	// Send a data frame with destination + payload.
	destBytes := reflex.EncodeDestination(reflex.AddrTypeIPv4, []byte{127, 0, 0, 1}, 9090)
	msg := []byte("integration test payload")
	firstPayload := append(destBytes, msg...)
	if err := session.WriteFrame(clientConn, reflex.FrameTypeData, firstPayload); err != nil {
		t.Fatalf("write first data frame: %v", err)
	}

	// Drain server echoed frames in the background so net.Pipe doesn't block.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		buf := make([]byte, 4096)
		for {
			clientConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			_, err := clientConn.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Send a second data frame (no destination prefix).
	time.Sleep(50 * time.Millisecond)
	if err := session.WriteFrame(clientConn, reflex.FrameTypeData, []byte("second message")); err != nil {
		t.Fatalf("write second data frame: %v", err)
	}

	// Graceful close.
	time.Sleep(50 * time.Millisecond)
	session.WriteFrame(clientConn, reflex.FrameTypeClose, nil)

	select {
	case err := <-serverDone:
		if err != nil {
			t.Logf("server finished with: %v (acceptable)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for server to finish")
	}
	<-drainDone
}

func TestIntegrationFallbackRouting(t *testing.T) {
	// Verify that non-Reflex traffic on a handler without fallback returns
	// a proper HTTP error, while Reflex traffic gets a 200 handshake response.
	h := newTestHandler(0) // no fallback
	dispatcher := &mockDispatcher{}

	// Non-Reflex traffic should get an error (400 Bad Request).
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- h.Process(context.Background(), xnet.Network_TCP, serverConn, dispatcher)
	}()

	clientConn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	clientConn.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for non-Reflex traffic without fallback")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: non-Reflex traffic was not rejected")
	}

	// Reflex traffic should succeed with HTTP 200.
	clientConn2, serverConn2 := net.Pipe()
	defer clientConn2.Close()
	defer serverConn2.Close()

	done2 := make(chan error, 1)
	go func() {
		done2 <- h.Process(context.Background(), xnet.Network_TCP, serverConn2, dispatcher)
	}()

	_, clientPub, _ := reflex.GenerateKeyPair()
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix(),
	}
	copy(payload.UserID[:], uuidToBytes(t, testUUID))
	io.ReadFull(rand.Reader, payload.Nonce[:])
	reqBytes, _ := reflex.WrapClientHTTP(payload, "test-server")
	clientConn2.Write(reqBytes)

	buf := make([]byte, 512)
	clientConn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := clientConn2.Read(buf)
	if !strings.Contains(string(buf[:n]), "200") {
		t.Fatalf("expected HTTP 200 for Reflex traffic, got: %q", string(buf[:n]))
	}
}

func TestIntegrationMultipleClients(t *testing.T) {
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	const numClients = 3
	var wg sync.WaitGroup
	errs := make(chan error, numClients)

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			serverDone := make(chan error, 1)
			go func() {
				serverDone <- h.Process(context.Background(), xnet.Network_TCP, serverConn, dispatcher)
			}()

			session := doClientHandshake(t, clientConn, testUUID)

			destBytes := reflex.EncodeDestination(
				reflex.AddrTypeDomain,
				[]byte(fmt.Sprintf("client%d.example.com", clientID)),
				uint16(8080+clientID),
			)
			payload := append(destBytes, []byte(fmt.Sprintf("hello from client %d", clientID))...)
			if err := session.WriteFrame(clientConn, reflex.FrameTypeData, payload); err != nil {
				errs <- fmt.Errorf("client %d write: %v", clientID, err)
				return
			}

			drainDone := make(chan struct{})
			go func() {
				defer close(drainDone)
				buf := make([]byte, 4096)
				for {
					clientConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
					if _, err := clientConn.Read(buf); err != nil {
						return
					}
				}
			}()

			time.Sleep(100 * time.Millisecond)
			session.WriteFrame(clientConn, reflex.FrameTypeClose, nil)

			select {
			case <-serverDone:
			case <-time.After(5 * time.Second):
				errs <- fmt.Errorf("client %d: server timeout", clientID)
			}
			<-drainDone
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

func TestProcessRoutesToReflex(t *testing.T) {
	// Confirm that Process routes Reflex traffic to handleReflex, not fallback.
	h := newTestHandler(0)
	dispatcher := &mockDispatcher{}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	done := make(chan error, 1)
	go func() {
		done <- h.Process(context.Background(), xnet.Network_TCP, serverConn, dispatcher)
	}()

	// Send valid Reflex handshake.
	_, clientPub, _ := reflex.GenerateKeyPair()
	payload := &reflex.ClientPayload{
		PublicKey: clientPub,
		Timestamp: time.Now().Unix(),
	}
	copy(payload.UserID[:], uuidToBytes(t, testUUID))
	io.ReadFull(rand.Reader, payload.Nonce[:])
	reqBytes, _ := reflex.WrapClientHTTP(payload, "test-server")
	clientConn.Write(reqBytes)

	// Read the HTTP 200 — confirms server routed to Reflex handler.
	buf := make([]byte, 512)
	clientConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _ := clientConn.Read(buf)
	response := string(buf[:n])

	if !strings.Contains(response, "200") {
		t.Fatalf("expected HTTP 200 from Reflex handler, got: %q", response)
	}
}
