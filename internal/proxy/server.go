package proxy

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultListenAddr keeps proxy listeners bound to localhost unless configured otherwise.
	DefaultListenAddr = "127.0.0.1:0"

	// DefaultRateLimitPerMinute is a conservative per-client connection budget.
	DefaultRateLimitPerMinute = 120
	// DefaultRateLimitBurst allows short local bursts while still bounding abuse.
	DefaultRateLimitBurst = 20

	socksVersion           = byte(0x05)
	socksMethodNoAuth      = byte(0x00)
	socksMethodUserPass    = byte(0x02)
	socksMethodNoAccept    = byte(0xff)
	socksCommandConnect    = byte(0x01)
	socksReplySuccess      = byte(0x00)
	socksReplyGeneralError = byte(0x01)
	socksReplyUnsupported  = byte(0x07)
	socksAtypIPv4          = byte(0x01)
	socksAtypDomain        = byte(0x03)
	socksAtypIPv6          = byte(0x04)
)

var defaultAllowedClientCIDRs = []string{"127.0.0.0/8", "::1/128"}

// Config controls local proxy server behavior.
type Config struct {
	ListenAddr         string
	Username           string
	Password           string
	AllowedClientCIDRs []string
	RateLimitPerMinute int
	RateLimitBurst     int
}

// AuthEnabled reports whether proxy authentication is configured.
func (c Config) AuthEnabled() bool {
	return c.Username != "" && c.Password != ""
}

// Dialer abstracts outbound tunnel dialing for tests and future WARP integration.
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Server owns validated proxy configuration and outbound dialing.
type Server struct {
	config   Config
	dialer   Dialer
	allowNet []*net.IPNet
	limiter  *rateLimiter
}

type netDialer struct{}

func (netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, address)
}

// NewServer validates configuration and creates a proxy server core.
func NewServer(config Config, dialer Dialer) (*Server, error) {
	validated, err := validateConfig(config)
	if err != nil {
		return nil, err
	}
	if dialer == nil {
		dialer = netDialer{}
	}
	allowNet, err := parseAllowedClientCIDRs(validated.AllowedClientCIDRs)
	if err != nil {
		return nil, err
	}
	return &Server{config: validated, dialer: dialer, allowNet: allowNet, limiter: newRateLimiter(validated.RateLimitPerMinute, validated.RateLimitBurst, time.Now)}, nil
}

// Config returns the server's validated configuration.
func (s *Server) Config() Config {
	return s.config
}

// Listen creates a TCP listener for the validated proxy listen address.
func (s *Server) Listen(ctx context.Context) (net.Listener, error) {
	var listenConfig net.ListenConfig
	return listenConfig.Listen(ctx, "tcp", s.config.ListenAddr)
}

// ServeSOCKS5 accepts SOCKS5 client connections until the listener fails or context is canceled.
func (s *Server) ServeSOCKS5(ctx context.Context, listener net.Listener) error {
	return s.serve(ctx, listener, s.ServeSOCKS5Conn)
}

// ServeHTTP accepts HTTP proxy client connections until the listener fails or context is canceled.
func (s *Server) ServeHTTP(ctx context.Context, listener net.Listener) error {
	return s.serve(ctx, listener, s.ServeHTTPConn)
}

func (s *Server) serve(ctx context.Context, listener net.Listener, handler func(context.Context, net.Conn) error) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			listener.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go serveConnection(ctx, conn, handler)
	}
}

func serveConnection(ctx context.Context, conn net.Conn, handler func(context.Context, net.Conn) error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			_ = conn.Close()
		}
	}()
	_ = handler(ctx, conn)
}

func validateConfig(config Config) (Config, error) {
	config.ListenAddr = strings.TrimSpace(config.ListenAddr)
	if config.ListenAddr == "" {
		config.ListenAddr = DefaultListenAddr
	}
	config.Username = strings.TrimSpace(config.Username)
	config.Password = strings.TrimSpace(config.Password)
	config.AllowedClientCIDRs = cleanCIDRs(config.AllowedClientCIDRs)
	if len(config.AllowedClientCIDRs) == 0 {
		config.AllowedClientCIDRs = append([]string(nil), defaultAllowedClientCIDRs...)
	}
	if _, err := parseAllowedClientCIDRs(config.AllowedClientCIDRs); err != nil {
		return Config{}, err
	}
	if config.RateLimitPerMinute < 0 {
		return Config{}, errors.New("proxy rate limit per minute cannot be negative")
	}
	if config.RateLimitBurst < 0 {
		return Config{}, errors.New("proxy rate limit burst cannot be negative")
	}
	if config.RateLimitPerMinute == 0 {
		config.RateLimitPerMinute = DefaultRateLimitPerMinute
	}
	if config.RateLimitBurst == 0 {
		config.RateLimitBurst = DefaultRateLimitBurst
	}

	if (config.Username == "") != (config.Password == "") {
		return Config{}, errors.New("proxy authentication requires both username and password")
	}

	host, _, err := net.SplitHostPort(config.ListenAddr)
	if err != nil {
		return Config{}, fmt.Errorf("proxy listen address must be host:port: %w", err)
	}
	if !isLocalBindHost(host) {
		if !config.AuthEnabled() {
			return Config{}, errors.New("authentication is required for non-localhost proxy bind addresses")
		}
		if err := validateRemoteProxyCredentials(config.Username, config.Password); err != nil {
			return Config{}, err
		}
	}

	return config, nil
}

func isLocalBindHost(host string) bool {
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateRemoteProxyCredentials(username, password string) error {
	if len(username) < 3 {
		return errors.New("proxy authentication username is too weak for non-localhost bind addresses")
	}
	if len(password) < 12 {
		return errors.New("proxy authentication password is too weak for non-localhost bind addresses")
	}
	if constantTimeEqual(strings.ToLower(username), strings.ToLower(password)) {
		return errors.New("proxy authentication username and password must differ for non-localhost bind addresses")
	}
	switch strings.ToLower(password) {
	case "password", "password123", "changeme", "letmein", "warpshift", "adminadmin":
		return errors.New("proxy authentication password is too weak for non-localhost bind addresses")
	}
	return nil
}

func cleanCIDRs(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}

func parseAllowedClientCIDRs(values []string) ([]*net.IPNet, error) {
	networks := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			value = fmt.Sprintf("%s/%d", ip.String(), bits)
		}
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("proxy allowed client CIDR %q is invalid", value)
		}
		networks = append(networks, network)
	}
	return networks, nil
}

// ServeSOCKS5Conn handles one SOCKS5 client connection.
func (s *Server) ServeSOCKS5Conn(ctx context.Context, client net.Conn) error {
	relayStarted := false
	defer func() {
		if !relayStarted {
			_ = client.Close()
		}
	}()
	if err := s.checkClientAccess(client); err != nil {
		return err
	}

	reader := bufio.NewReader(client)
	if err := s.handleSOCKS5Greeting(reader, client); err != nil {
		return err
	}

	address, reply, err := readSOCKS5Request(reader)
	if err != nil {
		_ = writeSOCKS5Reply(client, reply)
		return err
	}

	target, err := s.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		_ = writeSOCKS5Reply(client, socksReplyGeneralError)
		return err
	}

	if err := writeSOCKS5Reply(client, socksReplySuccess); err != nil {
		_ = target.Close()
		return err
	}
	relayStarted = true
	return relay(ctx, client, target, reader)
}

func (s *Server) handleSOCKS5Greeting(reader *bufio.Reader, client io.Writer) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != socksVersion {
		return errors.New("unsupported SOCKS version")
	}

	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}

	selected := socksMethodNoAccept
	if s.config.AuthEnabled() {
		if containsMethod(methods, socksMethodUserPass) {
			selected = socksMethodUserPass
		}
	} else if containsMethod(methods, socksMethodNoAuth) {
		selected = socksMethodNoAuth
	}

	if _, err := client.Write([]byte{socksVersion, selected}); err != nil {
		return err
	}
	if selected == socksMethodNoAccept {
		return errors.New("SOCKS5 authentication method not accepted")
	}
	if selected == socksMethodUserPass {
		return s.handleSOCKS5UserPass(reader, client)
	}
	return nil
}

func (s *Server) handleSOCKS5UserPass(reader *bufio.Reader, client io.Writer) error {
	version, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if version != 0x01 {
		_, _ = client.Write([]byte{0x01, 0x01})
		return errors.New("unsupported SOCKS5 username/password version")
	}

	username, err := readSOCKS5Credential(reader)
	if err != nil {
		return err
	}
	password, err := readSOCKS5Credential(reader)
	if err != nil {
		return err
	}

	if constantTimeEqual(username, s.config.Username) && constantTimeEqual(password, s.config.Password) {
		_, err = client.Write([]byte{0x01, 0x00})
		return err
	}
	_, _ = client.Write([]byte{0x01, 0x01})
	return errors.New("SOCKS5 authentication failed")
}

func readSOCKS5Credential(reader *bufio.Reader) (string, error) {
	length, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	value := make([]byte, int(length))
	_, err = io.ReadFull(reader, value)
	return string(value), err
}

func readSOCKS5Request(reader *bufio.Reader) (string, byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return "", socksReplyGeneralError, err
	}
	if header[0] != socksVersion {
		return "", socksReplyGeneralError, errors.New("unsupported SOCKS version")
	}
	if header[1] != socksCommandConnect {
		return "", socksReplyUnsupported, errors.New("unsupported SOCKS command")
	}

	host, err := readSOCKS5Address(reader, header[3])
	if err != nil {
		return "", socksReplyGeneralError, err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, portBytes); err != nil {
		return "", socksReplyGeneralError, err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	return net.JoinHostPort(host, strconv.Itoa(port)), socksReplySuccess, nil
}

func readSOCKS5Address(reader *bufio.Reader, addressType byte) (string, error) {
	switch addressType {
	case socksAtypIPv4:
		ip := make([]byte, net.IPv4len)
		_, err := io.ReadFull(reader, ip)
		return net.IP(ip).String(), err
	case socksAtypDomain:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		domain := make([]byte, int(length))
		_, err = io.ReadFull(reader, domain)
		return string(domain), err
	case socksAtypIPv6:
		ip := make([]byte, net.IPv6len)
		_, err := io.ReadFull(reader, ip)
		return net.IP(ip).String(), err
	default:
		return "", errors.New("unsupported SOCKS address type")
	}
}

func writeSOCKS5Reply(writer io.Writer, reply byte) error {
	_, err := writer.Write([]byte{socksVersion, reply, 0x00, socksAtypIPv4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func containsMethod(methods []byte, method byte) bool {
	for _, candidate := range methods {
		if candidate == method {
			return true
		}
	}
	return false
}

// ServeHTTPConn handles one HTTP proxy client connection, including CONNECT tunnels.
func (s *Server) ServeHTTPConn(ctx context.Context, client net.Conn) error {
	defer client.Close()
	if err := s.checkClientAccess(client); err != nil {
		_ = writeHTTPError(client, http.StatusTooManyRequests)
		return err
	}

	reader := bufio.NewReader(client)
	request, err := http.ReadRequest(reader)
	if err != nil {
		return err
	}
	defer request.Body.Close()

	if !s.authorizedHTTP(request) {
		return writeHTTPProxyAuthRequired(client)
	}

	if request.Method == http.MethodConnect {
		return s.handleHTTPConnect(ctx, client, reader, request)
	}
	return s.handleHTTPForward(ctx, client, request)
}

func (s *Server) handleHTTPConnect(ctx context.Context, client net.Conn, reader *bufio.Reader, request *http.Request) error {
	address := request.Host
	if address == "" && request.URL != nil {
		address = request.URL.Host
	}
	address, err := withDefaultPort(address, "443")
	if err != nil {
		return writeHTTPError(client, http.StatusBadRequest)
	}

	target, err := s.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return writeHTTPError(client, http.StatusBadGateway)
	}

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = target.Close()
		return err
	}
	return relay(ctx, client, target, reader)
}

func (s *Server) handleHTTPForward(ctx context.Context, client net.Conn, request *http.Request) error {
	if request.URL == nil || !strings.EqualFold(request.URL.Scheme, "http") || request.URL.Host == "" {
		return writeHTTPError(client, http.StatusBadRequest)
	}

	address, err := withDefaultPort(request.URL.Host, "80")
	if err != nil {
		return writeHTTPError(client, http.StatusBadRequest)
	}
	target, err := s.dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return writeHTTPError(client, http.StatusBadGateway)
	}
	defer target.Close()

	request.RequestURI = ""
	request.Header.Del("Proxy-Authorization")
	request.Header.Del("Proxy-Connection")
	if err := request.Write(target); err != nil {
		return err
	}
	_, err = io.Copy(client, target)
	return normalizeCopyError(err)
}

func (s *Server) authorizedHTTP(request *http.Request) bool {
	if !s.config.AuthEnabled() {
		return true
	}

	header := request.Header.Get("Proxy-Authorization")
	scheme, encoded, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return false
	}
	return constantTimeEqual(string(decoded), s.config.Username+":"+s.config.Password)
}

func writeHTTPProxyAuthRequired(writer io.Writer) error {
	_, err := io.WriteString(writer, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"WarpShift-TUI\"\r\nContent-Length: 0\r\n\r\n")
	return err
}

func writeHTTPError(writer io.Writer, statusCode int) error {
	statusText := http.StatusText(statusCode)
	_, err := fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n\r\n", statusCode, statusText)
	return err
}

func withDefaultPort(address, defaultPort string) (string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", errors.New("empty address")
	}
	if _, _, err := net.SplitHostPort(address); err == nil {
		return address, nil
	}
	if strings.Contains(address, ":") && !strings.HasPrefix(address, "[") {
		if ip := net.ParseIP(address); ip != nil {
			return net.JoinHostPort(address, defaultPort), nil
		}
	}
	return net.JoinHostPort(address, defaultPort), nil
}

func (s *Server) checkClientAccess(conn net.Conn) error {
	addr := conn.RemoteAddr()
	clientIP := clientIPFromAddr(addr)
	if clientIP == nil {
		return nil
	}
	allowed := false
	for _, network := range s.allowNet {
		if network.Contains(clientIP) {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("proxy client not allowed")
	}
	if s.limiter != nil && !s.limiter.allow(clientIP.String()) {
		return errors.New("proxy client rate limit exceeded")
	}
	return nil
}

func clientIPFromAddr(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	switch value := addr.(type) {
	case *net.TCPAddr:
		return value.IP
	case *net.UDPAddr:
		return value.IP
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return nil
		}
		return net.ParseIP(host)
	}
}

type rateLimiter struct {
	mu        sync.Mutex
	perMinute int
	burst     int
	now       func() time.Time
	buckets   map[string]*rateBucket
}

type rateBucket struct {
	tokens  float64
	updated time.Time
}

func newRateLimiter(perMinute, burst int, now func() time.Time) *rateLimiter {
	if perMinute <= 0 || burst <= 0 {
		return nil
	}
	if now == nil {
		now = time.Now
	}
	return &rateLimiter{perMinute: perMinute, burst: burst, now: now, buckets: map[string]*rateBucket{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	bucket := l.buckets[key]
	if bucket == nil {
		bucket = &rateBucket{tokens: float64(l.burst), updated: now}
		l.buckets[key] = bucket
	}
	elapsed := now.Sub(bucket.updated)
	if elapsed > 0 {
		bucket.tokens += elapsed.Minutes() * float64(l.perMinute)
		if bucket.tokens > float64(l.burst) {
			bucket.tokens = float64(l.burst)
		}
		bucket.updated = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func relay(ctx context.Context, client net.Conn, target net.Conn, clientReader io.Reader) error {
	errCh := make(chan error, 2)
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			client.Close()
			target.Close()
		})
	}

	go func() {
		_, err := io.Copy(target, clientReader)
		errCh <- normalizeCopyError(err)
		closeBoth()
	}()
	go func() {
		_, err := io.Copy(client, target)
		errCh <- normalizeCopyError(err)
		closeBoth()
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		closeBoth()
		<-errCh
		return ctx.Err()
	}
}

func normalizeCopyError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "closed pipe") {
		return nil
	}
	return err
}

func constantTimeEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
