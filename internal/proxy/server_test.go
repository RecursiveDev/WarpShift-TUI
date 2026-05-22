package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingDialer struct {
	mu      sync.Mutex
	conn    net.Conn
	network string
	address string
	calls   int
}

func (d *recordingDialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	d.network = network
	d.address = address
	return d.conn, nil
}

func (d *recordingDialer) snapshot() (string, string, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.network, d.address, d.calls
}

func TestNewServerDefaultsToLocalhost(t *testing.T) {
	server, err := NewServer(Config{}, &recordingDialer{})
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	if got, want := server.Config().ListenAddr, "127.0.0.1:0"; got != want {
		t.Fatalf("ListenAddr = %q, want %q", got, want)
	}
}

func TestServeRecoversPanickingConnectionHandlerAndContinues(t *testing.T) {
	server, err := NewServer(Config{}, &recordingDialer{})
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := make(chan struct{}, 2)
	done := make(chan error, 1)
	go func() {
		done <- server.serve(ctx, listener, func(_ context.Context, _ net.Conn) error {
			accepted <- struct{}{}
			panic("forced handler panic")
		})
	}()

	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dial connection %d: %v", i+1, err)
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		select {
		case <-accepted:
		case <-time.After(time.Second):
			conn.Close()
			t.Fatalf("connection %d was not accepted", i+1)
		}
		if _, err := conn.Read([]byte{0}); err == nil {
			conn.Close()
			t.Fatalf("connection %d stayed open after handler panic", i+1)
		}
		conn.Close()
	}

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("serve error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serve did not return after context cancellation")
	}
}

func TestNewServerRejectsRemoteBindWithoutAuth(t *testing.T) {
	_, err := NewServer(Config{ListenAddr: "0.0.0.0:1080"}, &recordingDialer{})
	if err == nil {
		t.Fatal("expected remote bind without authentication to be rejected")
	}
	if !strings.Contains(err.Error(), "authentication") {
		t.Fatalf("error = %q, want authentication guidance", err.Error())
	}
}

func TestNewServerAcceptsRemoteBindWithAuth(t *testing.T) {
	_, err := NewServer(Config{ListenAddr: "0.0.0.0:1080", Username: "operator", Password: "strong-passphrase-123"}, &recordingDialer{})
	if err != nil {
		t.Fatalf("NewServer rejected authenticated remote bind: %v", err)
	}
}

func TestNewServerRejectsWeakRemoteCredentials(t *testing.T) {
	_, err := NewServer(Config{ListenAddr: "0.0.0.0:1080", Username: "user", Password: "pass"}, &recordingDialer{})
	if err == nil {
		t.Fatal("expected weak remote proxy credentials to be rejected")
	}
	if !strings.Contains(err.Error(), "too weak") {
		t.Fatalf("error = %q, want weak credential guidance", err.Error())
	}
}

func TestSOCKS5ConnectUsesDialerAndRelaysBytes(t *testing.T) {
	client, proxySide := net.Pipe()
	upstreamClient, upstreamProxy := net.Pipe()
	defer client.Close()
	defer upstreamClient.Close()
	deadline := time.Now().Add(2 * time.Second)
	client.SetDeadline(deadline)
	upstreamClient.SetDeadline(deadline)

	dialer := &recordingDialer{conn: upstreamProxy}
	server, err := NewServer(Config{}, dialer)
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- server.ServeSOCKS5Conn(context.Background(), proxySide) }()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	greetingReply := make([]byte, 2)
	if _, err := io.ReadFull(client, greetingReply); err != nil {
		t.Fatalf("read SOCKS5 greeting reply: %v", err)
	}
	if got, want := greetingReply, []byte{0x05, 0x00}; string(got) != string(want) {
		t.Fatalf("greeting reply = %v, want %v", got, want)
	}

	request := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.test"))}, []byte("example.test")...)
	request = append(request, 0x00, 0x50)
	if _, err := client.Write(request); err != nil {
		t.Fatalf("write SOCKS5 connect request: %v", err)
	}
	connectReply := make([]byte, 10)
	if _, err := io.ReadFull(client, connectReply); err != nil {
		t.Fatalf("read SOCKS5 connect reply: %v", err)
	}
	if connectReply[0] != 0x05 || connectReply[1] != 0x00 {
		t.Fatalf("connect reply = %v, want success", connectReply)
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write client payload: %v", err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(upstreamClient, payload); err != nil {
		t.Fatalf("read upstream payload: %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("upstream payload = %q, want ping", payload)
	}

	if _, err := upstreamClient.Write([]byte("pong")); err != nil {
		t.Fatalf("write upstream payload: %v", err)
	}
	payload = make([]byte, 4)
	if _, err := io.ReadFull(client, payload); err != nil {
		t.Fatalf("read client payload: %v", err)
	}
	if string(payload) != "pong" {
		t.Fatalf("client payload = %q, want pong", payload)
	}

	network, address, calls := dialer.snapshot()
	if network != "tcp" || address != "example.test:80" || calls != 1 {
		t.Fatalf("dialer = (%q, %q, %d), want (tcp, example.test:80, 1)", network, address, calls)
	}

	client.Close()
	upstreamClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 handler did not return after connections closed")
	}
}

func TestSOCKS5RejectsMissingAuthWhenConfigured(t *testing.T) {
	client, proxySide := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))

	dialer := &recordingDialer{}
	server, err := NewServer(Config{Username: "user", Password: "pass"}, dialer)
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- server.ServeSOCKS5Conn(context.Background(), proxySide) }()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(client, reply); err != nil {
		t.Fatalf("read SOCKS5 greeting reply: %v", err)
	}
	if got, want := reply, []byte{0x05, 0xff}; string(got) != string(want) {
		t.Fatalf("greeting reply = %v, want %v", got, want)
	}
	_, _, calls := dialer.snapshot()
	if calls != 0 {
		t.Fatalf("dialer calls = %d, want 0", calls)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 handler did not return after auth rejection")
	}
}

func TestHTTPConnectRequiresBasicAuthAndRelaysBytes(t *testing.T) {
	client, proxySide := net.Pipe()
	upstreamClient, upstreamProxy := net.Pipe()
	defer client.Close()
	defer upstreamClient.Close()
	deadline := time.Now().Add(2 * time.Second)
	client.SetDeadline(deadline)
	upstreamClient.SetDeadline(deadline)

	dialer := &recordingDialer{conn: upstreamProxy}
	server, err := NewServer(Config{Username: "user", Password: "pass"}, dialer)
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- server.ServeHTTPConn(context.Background(), proxySide) }()

	credential := base64.StdEncoding.EncodeToString([]byte("user:pass"))
	request := "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\nProxy-Authorization: Basic " + credential + "\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want 200", response.StatusCode)
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("write client payload: %v", err)
	}
	payload := make([]byte, 4)
	if _, err := io.ReadFull(upstreamClient, payload); err != nil {
		t.Fatalf("read upstream payload: %v", err)
	}
	if string(payload) != "ping" {
		t.Fatalf("upstream payload = %q, want ping", payload)
	}

	network, address, calls := dialer.snapshot()
	if network != "tcp" || address != "example.test:443" || calls != 1 {
		t.Fatalf("dialer = (%q, %q, %d), want (tcp, example.test:443, 1)", network, address, calls)
	}

	client.Close()
	upstreamClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTP CONNECT handler did not return after connections closed")
	}
}

func TestHTTPProxyForwardsAbsoluteURLWithoutProxyCredentials(t *testing.T) {
	client, proxySide := net.Pipe()
	upstreamClient, upstreamProxy := net.Pipe()
	defer client.Close()
	defer upstreamClient.Close()
	deadline := time.Now().Add(2 * time.Second)
	client.SetDeadline(deadline)
	upstreamClient.SetDeadline(deadline)

	dialer := &recordingDialer{conn: upstreamProxy}
	server, err := NewServer(Config{}, dialer)
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- server.ServeHTTPConn(context.Background(), proxySide) }()

	upstreamDone := make(chan error, 1)
	go func() {
		request, err := http.ReadRequest(bufio.NewReader(upstreamClient))
		if err != nil {
			upstreamDone <- err
			return
		}
		if request.Method != http.MethodGet || request.URL.RequestURI() != "/path?q=1" {
			upstreamDone <- io.ErrUnexpectedEOF
			return
		}
		if request.Header.Get("Proxy-Authorization") != "" {
			upstreamDone <- io.ErrShortBuffer
			return
		}
		_, err = upstreamClient.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		upstreamDone <- err
	}()

	request := "GET http://example.test/path?q=1 HTTP/1.1\r\nHost: example.test\r\nProxy-Authorization: Basic should-not-forward\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("write HTTP proxy request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("read HTTP proxy response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", response.StatusCode)
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "OK" {
		t.Fatalf("response body = %q, want OK", body)
	}

	select {
	case err := <-upstreamDone:
		if err != nil {
			t.Fatalf("upstream assertion failed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("upstream did not receive forwarded request")
	}

	network, address, calls := dialer.snapshot()
	if network != "tcp" || address != "example.test:80" || calls != 1 {
		t.Fatalf("dialer = (%q, %q, %d), want (tcp, example.test:80, 1)", network, address, calls)
	}

	client.Close()
	upstreamClient.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTP handler did not return after forwarding response")
	}
}

func TestServerRejectsClientsOutsideAllowlist(t *testing.T) {
	client, proxySide := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(2 * time.Second))

	dialer := &recordingDialer{}
	server, err := NewServer(Config{AllowedClientCIDRs: []string{"127.0.0.0/8"}}, dialer)
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	remote := &remoteAddrConn{Conn: proxySide, remote: &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 53000}}
	done := make(chan error, 1)
	go func() { done <- server.ServeSOCKS5Conn(context.Background(), remote) }()

	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err == nil {
		reply := make([]byte, 2)
		if _, err := io.ReadFull(client, reply); err == nil {
			t.Fatalf("unexpected SOCKS5 reply for blocked client: %v", reply)
		}
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("handler error = %v, want allowlist rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 handler did not return after allowlist rejection")
	}
	_, _, calls := dialer.snapshot()
	if calls != 0 {
		t.Fatalf("dialer calls = %d, want 0", calls)
	}
}

func TestHTTPRateLimitReturnsTooManyRequests(t *testing.T) {
	dialer := &recordingDialer{}
	server, err := NewServer(Config{RateLimitPerMinute: 1, RateLimitBurst: 1}, dialer)
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}

	firstClient, firstProxy := net.Pipe()
	firstClient.SetDeadline(time.Now().Add(2 * time.Second))
	firstProxy = &remoteAddrConn{Conn: firstProxy, remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53001}}
	firstDone := make(chan error, 1)
	go func() { firstDone <- server.ServeHTTPConn(context.Background(), firstProxy) }()
	if _, err := firstClient.Write([]byte("bad request\r\n\r\n")); err != nil {
		t.Fatalf("write first HTTP request: %v", err)
	}
	firstClient.Close()
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first HTTP handler did not finish")
	}

	secondClient, secondProxy := net.Pipe()
	defer secondClient.Close()
	secondClient.SetDeadline(time.Now().Add(2 * time.Second))
	secondProxy = &remoteAddrConn{Conn: secondProxy, remote: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53002}}
	secondDone := make(chan error, 1)
	go func() { secondDone <- server.ServeHTTPConn(context.Background(), secondProxy) }()

	response, err := http.ReadResponse(bufio.NewReader(secondClient), nil)
	if err != nil {
		t.Fatalf("read rate-limit response: %v", err)
	}
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("HTTP status = %d, want 429", response.StatusCode)
	}
	select {
	case err := <-secondDone:
		if err == nil || !strings.Contains(err.Error(), "rate limit") {
			t.Fatalf("handler error = %v, want rate-limit rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second HTTP handler did not return after rate limit")
	}
}

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr {
	return c.remote
}
