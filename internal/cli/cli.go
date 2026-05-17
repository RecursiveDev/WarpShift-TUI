package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/RecursiveDev/WarpShift-TUI/internal/app"
	"github.com/RecursiveDev/WarpShift-TUI/internal/config"
	"github.com/RecursiveDev/WarpShift-TUI/internal/proxy"
	"github.com/RecursiveDev/WarpShift-TUI/internal/tui"
	"github.com/RecursiveDev/WarpShift-TUI/internal/tunnel"
	"github.com/RecursiveDev/WarpShift-TUI/internal/warp"
)

// Option customizes command dependencies for tests and future integrations.
type Option func(*Command)

// TUILauncher starts the TUI from an injected/static snapshot.
type TUILauncher func(context.Context, tui.Snapshot) error

// EndpointProbe probes one endpoint. Tests inject this to avoid live network access.
type EndpointProbe func(context.Context, warp.Endpoint) (time.Duration, error)

// ProxyDialerBuilder constructs the outbound proxy dialer from imported WARP identity material.
type ProxyDialerBuilder func(context.Context, warp.Identity, warp.Endpoint, tunnel.Config) (proxy.Dialer, error)

// Command provides the top-level command-line surface without calling os.Exit.
type Command struct {
	app                *app.App
	stdout             io.Writer
	stderr             io.Writer
	tuiLauncher        TUILauncher
	endpointProbe      EndpointProbe
	proxyDialerBuilder ProxyDialerBuilder
}

// WithTUILauncher injects a TUI launcher.
func WithTUILauncher(launcher TUILauncher) Option {
	return func(c *Command) {
		if launcher != nil {
			c.tuiLauncher = launcher
		}
	}
}

// WithEndpointProbe injects endpoint probing for scan commands.
func WithEndpointProbe(probe EndpointProbe) Option {
	return func(c *Command) {
		if probe != nil {
			c.endpointProbe = probe
		}
	}
}

// WithProxyDialerBuilder injects WARP tunnel dialer construction for proxy commands.
func WithProxyDialerBuilder(builder ProxyDialerBuilder) Option {
	return func(c *Command) {
		if builder != nil {
			c.proxyDialerBuilder = builder
		}
	}
}

// New creates a CLI command that writes to the provided streams.
func New(application *app.App, stdout, stderr io.Writer, options ...Option) *Command {
	command := &Command{
		app:                application,
		stdout:             stdout,
		stderr:             stderr,
		tuiLauncher:        tui.Run,
		endpointProbe:      disabledEndpointProbe,
		proxyDialerBuilder: defaultProxyDialerBuilder,
	}
	for _, option := range options {
		option(command)
	}
	return command
}

// Run executes the command and returns a process exit code.
func (c *Command) Run(ctx context.Context, args []string) int {
	if err := ctx.Err(); err != nil {
		fmt.Fprintf(c.stderr, "warpshift: %v\n", err)
		return 1
	}
	if len(args) == 0 {
		c.printHelp()
		return 0
	}

	switch args[0] {
	case "help":
		c.printHelp()
		return 0
	case "version":
		return c.runVersion()
	case "tui":
		return c.runTUI(ctx, args[1:])
	case "config":
		return c.runConfig(args[1:])
	case "identity":
		return c.runIdentity(args[1:])
	case "wireguard", "wg":
		return c.runWireGuard(args[1:])
	case "trace":
		return c.runTrace(args[1:])
	case "endpoint":
		return c.runEndpoint(ctx, args[1:])
	case "proxy":
		return c.runProxy(ctx, args[1:])
	default:
		return c.runTopLevelFlags(args)
	}
}

func (c *Command) runTopLevelFlags(args []string) int {
	flags := flag.NewFlagSet("warpshift", flag.ContinueOnError)
	flags.SetOutput(c.stderr)
	showHelp := flags.Bool("help", false, "show help")
	showVersion := flags.Bool("version", false, "show version")
	flags.BoolVar(showHelp, "h", false, "show help")
	if err := flags.Parse(args); err != nil {
		fmt.Fprintf(c.stderr, "warpshift: unknown flag or invalid arguments: %v\n", err)
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(c.stderr, "warpshift: unknown command %q\n", flags.Arg(0))
		return 2
	}
	if *showHelp {
		c.printHelp()
		return 0
	}
	if *showVersion {
		return c.runVersion()
	}
	c.printHelp()
	return 0
}

func (c *Command) runVersion() int {
	fmt.Fprintf(c.stdout, "%s %s\n", c.app.Name(), c.app.Version())
	return 0
}

func (c *Command) runTUI(ctx context.Context, args []string) int {
	flags := c.newFlagSet("tui")
	if err := flags.Parse(args); err != nil {
		return c.usageError("tui", err)
	}
	if flags.NArg() != 0 {
		return c.unexpectedArg("tui", flags.Arg(0))
	}
	if err := c.tuiLauncher(ctx, c.defaultSnapshot()); err != nil {
		fmt.Fprintf(c.stderr, "warpshift tui: %v\n", err)
		return 1
	}
	fmt.Fprintln(c.stdout, "TUI exited")
	return 0
}

func (c *Command) runConfig(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift config: expected subcommand validate")
		return 2
	}
	switch args[0] {
	case "validate":
		flags := c.newFlagSet("config validate")
		path := flags.String("config", "configs/warpshift.example.toml", "config file path")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("config validate", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("config validate", flags.Arg(0))
		}
		settings, err := config.Load(*path)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift config validate: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "configuration valid: %s (startup=%s, proxy_listen=%s)\n", *path, settings.App.StartupMode, settings.Proxy.ListenAddress)
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift config: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (c *Command) runIdentity(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift identity: expected subcommand import or inspect")
		return 2
	}
	switch args[0] {
	case "import":
		flags := c.newFlagSet("identity import")
		input := flags.String("input", "", "manual identity JSON path")
		store := flags.String("store", config.DefaultSettings().Identity.StorePath, "identity store path")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("identity import", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("identity import", flags.Arg(0))
		}
		if strings.TrimSpace(*input) == "" {
			fmt.Fprintln(c.stderr, "warpshift identity import: --input is required for manual identity import only")
			return 2
		}
		if _, err := warp.ImportManualIdentityFile(*input, *store); err != nil {
			fmt.Fprintf(c.stderr, "warpshift identity import: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "manual identity imported to %s\n", *store)
		return 0
	case "inspect":
		flags := c.newFlagSet("identity inspect")
		store := flags.String("store", config.DefaultSettings().Identity.StorePath, "identity store path")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("identity inspect", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("identity inspect", flags.Arg(0))
		}
		identity, err := warp.LoadIdentity(*store)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift identity inspect: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "identity present: endpoint=%s interface_addresses=%d dns=%d\n", identity.Endpoint, len(identity.InterfaceAddresses), len(identity.DNS))
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift identity: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (c *Command) runWireGuard(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift wireguard: expected subcommand export")
		return 2
	}
	if args[0] != "export" {
		fmt.Fprintf(c.stderr, "warpshift wireguard: unknown subcommand %q\n", args[0])
		return 2
	}
	defaults := config.DefaultSettings()
	flags := c.newFlagSet("wireguard export")
	identityPath := flags.String("identity", defaults.Identity.StorePath, "identity store path")
	output := flags.String("output", defaults.WireGuard.OutputPath, "WireGuard profile output path")
	endpoint := flags.String("endpoint", defaults.WireGuard.Endpoint, "WireGuard peer endpoint")
	if err := flags.Parse(args[1:]); err != nil {
		return c.usageError("wireguard export", err)
	}
	if flags.NArg() != 0 {
		return c.unexpectedArg("wireguard export", flags.Arg(0))
	}
	identity, err := warp.LoadIdentity(*identityPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift wireguard export: %v\n", err)
		return 2
	}
	profile := warp.WireGuardProfileConfig{
		AllowedIPs:          defaults.WireGuard.AllowedIPs,
		DNS:                 defaults.WireGuard.DNS,
		Endpoint:            *endpoint,
		MTU:                 defaults.WireGuard.MTU,
		PersistentKeepalive: defaults.WireGuard.PersistentKeepalive,
	}
	if err := warp.ExportWireGuardProfile(*output, *identity, profile); err != nil {
		fmt.Fprintf(c.stderr, "warpshift wireguard export: %v\n", err)
		return 2
	}
	fmt.Fprintf(c.stdout, "WireGuard profile exported to %s\n", *output)
	return 0
}

func (c *Command) runTrace(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift trace: expected subcommand parse or status")
		return 2
	}
	if args[0] != "parse" && args[0] != "status" {
		fmt.Fprintf(c.stderr, "warpshift trace: unknown subcommand %q\n", args[0])
		return 2
	}
	flags := c.newFlagSet("trace " + args[0])
	path := flags.String("file", "", "Cloudflare trace fixture path")
	if err := flags.Parse(args[1:]); err != nil {
		return c.usageError("trace "+args[0], err)
	}
	if flags.NArg() != 0 {
		return c.unexpectedArg("trace "+args[0], flags.Arg(0))
	}
	if strings.TrimSpace(*path) == "" {
		fmt.Fprintf(c.stderr, "warpshift trace %s: --file is required; live trace fetching is not performed\n", args[0])
		return 2
	}
	data, err := os.ReadFile(*path)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift trace %s: %v\n", args[0], err)
		return 2
	}
	health, err := warp.ParseCloudflareTrace(string(data))
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift trace %s: %v\n", args[0], err)
		return 2
	}
	fmt.Fprintf(c.stdout, "warp=%s healthy=%t\n", health.WARP, health.Healthy())
	return 0
}

func (c *Command) runEndpoint(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift endpoint: expected subcommand scan")
		return 2
	}
	if args[0] != "scan" {
		fmt.Fprintf(c.stderr, "warpshift endpoint: unknown subcommand %q\n", args[0])
		return 2
	}
	flags := c.newFlagSet("endpoint scan")
	configPath := flags.String("config", "", "optional TOML config path for endpoint static sources")
	static := flags.String("static", "", "comma-separated static endpoints; overrides config endpoint.static")
	if err := flags.Parse(args[1:]); err != nil {
		return c.usageError("endpoint scan", err)
	}
	if flags.NArg() != 0 {
		return c.unexpectedArg("endpoint scan", flags.Arg(0))
	}
	settings := config.DefaultSettings()
	if strings.TrimSpace(*configPath) != "" {
		loaded, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift endpoint scan: %v\n", err)
			return 2
		}
		settings = loaded
	}
	staticSources := *static
	if strings.TrimSpace(staticSources) == "" {
		staticSources = strings.Join(settings.Endpoint.Static, ",")
	}
	endpoints, err := parseStaticEndpoints(staticSources)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift endpoint scan: %v\n", err)
		return 2
	}
	scanner, err := warp.NewScanner(warp.ProbeFunc(c.endpointProbe))
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift endpoint scan: %v\n", err)
		return 2
	}
	for _, result := range warp.RankByRTT(scanner.Scan(ctx, endpoints)) {
		if result.Healthy {
			fmt.Fprintf(c.stdout, "%s healthy %s\n", result.Endpoint.String(), result.RTT)
			continue
		}
		fmt.Fprintf(c.stdout, "%s unhealthy %s\n", result.Endpoint.String(), result.Error)
	}
	return 0
}

func (c *Command) runProxy(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift proxy: expected subcommand validate or start")
		return 2
	}
	switch args[0] {
	case "validate", "start":
		defaults := config.DefaultSettings()
		flags := c.newFlagSet("proxy " + args[0])
		listen := flags.String("listen", proxy.DefaultListenAddr, "proxy listen address; used for SOCKS5 unless --socks-listen/--http-listen selects listeners")
		socksListen := flags.String("socks-listen", "", "SOCKS5 proxy listen address")
		httpListen := flags.String("http-listen", "", "HTTP proxy listen address")
		username := flags.String("username", "", "proxy username")
		password := flags.String("password", "", "proxy password")
		identityPath := flags.String("identity", "", "stored WARP WireGuard identity path")
		endpointValue := flags.String("endpoint", "", "selected WARP endpoint host:port")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("proxy "+args[0], err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("proxy "+args[0], flags.Arg(0))
		}

		listeners := selectedProxyListeners(flags, *listen, *socksListen, *httpListen)
		if len(listeners) == 0 {
			fmt.Fprintf(c.stderr, "warpshift proxy %s: at least one proxy listener is required\n", args[0])
			return 2
		}

		baseConfig := proxy.Config{Username: *username, Password: *password}
		var firstConfig proxy.Config
		for i, listener := range listeners {
			candidate := baseConfig
			candidate.ListenAddr = listener.Address
			server, err := proxy.NewServer(candidate, nil)
			if err != nil {
				fmt.Fprintf(c.stderr, "warpshift proxy %s: %v\n", args[0], err)
				return 2
			}
			if i == 0 {
				firstConfig = server.Config()
			}
		}

		var outbound proxy.Dialer
		tunnelReady := false
		if strings.TrimSpace(*identityPath) != "" {
			identity, endpoint, tunnelConfig, err := c.loadProxyTunnelConfig(*identityPath, *endpointValue, defaults)
			if err != nil {
				fmt.Fprintf(c.stderr, "warpshift proxy %s: %v\n", args[0], err)
				return 2
			}
			if args[0] == "validate" {
				if _, err := tunnel.BuildConfig(*identity, endpoint, tunnelConfig); err != nil {
					fmt.Fprintf(c.stderr, "warpshift proxy validate: WARP tunnel configuration invalid: %v\n", err)
					return 2
				}
				tunnelReady = true
			} else {
				outbound, err = c.proxyDialerBuilder(ctx, *identity, endpoint, tunnelConfig)
				if err != nil {
					fmt.Fprintf(c.stderr, "warpshift proxy start: WARP tunnel backend unavailable: %v\n", err)
					return 1
				}
				if closer, ok := outbound.(interface{ Close() error }); ok {
					defer closer.Close()
				}
				tunnelReady = true
			}
		}

		if args[0] == "validate" {
			if tunnelReady {
				fmt.Fprintf(c.stdout, "proxy configuration valid: listen=%s auth=%t listeners=%d; warp tunnel configuration valid\n", firstConfig.ListenAddr, firstConfig.AuthEnabled(), len(listeners))
				return 0
			}
			fmt.Fprintf(c.stdout, "proxy configuration valid: listen=%s auth=%t listeners=%d\n", firstConfig.ListenAddr, firstConfig.AuthEnabled(), len(listeners))
			return 0
		}

		if err := c.serveProxy(ctx, listeners, baseConfig, outbound, tunnelReady); err != nil {
			fmt.Fprintf(c.stderr, "warpshift proxy start: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift proxy: unknown subcommand %q\n", args[0])
		return 2
	}
}

type proxyListenerSpec struct {
	Label   string
	Address string
	HTTP    bool
}

func selectedProxyListeners(flags *flag.FlagSet, listen, socksListen, httpListen string) []proxyListenerSpec {
	set := map[string]bool{}
	flags.Visit(func(flag *flag.Flag) { set[flag.Name] = true })

	listen = strings.TrimSpace(listen)
	socksListen = strings.TrimSpace(socksListen)
	httpListen = strings.TrimSpace(httpListen)

	listeners := []proxyListenerSpec{}
	if socksListen != "" {
		listeners = append(listeners, proxyListenerSpec{Label: "SOCKS5", Address: socksListen})
	} else if httpListen == "" || set["listen"] {
		listeners = append(listeners, proxyListenerSpec{Label: "SOCKS5", Address: listen})
	}
	if httpListen != "" {
		listeners = append(listeners, proxyListenerSpec{Label: "HTTP", Address: httpListen, HTTP: true})
	}
	return listeners
}

func (c *Command) serveProxy(ctx context.Context, specs []proxyListenerSpec, baseConfig proxy.Config, dialer proxy.Dialer, tunnelReady bool) error {
	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type runningListener struct {
		server   *proxy.Server
		listener net.Listener
		spec     proxyListenerSpec
	}
	running := make([]runningListener, 0, len(specs))
	for _, spec := range specs {
		cfg := baseConfig
		cfg.ListenAddr = spec.Address
		server, err := proxy.NewServer(cfg, dialer)
		if err != nil {
			return err
		}
		listener, err := server.Listen(serveCtx)
		if err != nil {
			for _, item := range running {
				_ = item.listener.Close()
			}
			return err
		}
		running = append(running, runningListener{server: server, listener: listener, spec: spec})
	}

	errCh := make(chan error, len(running))
	var wg sync.WaitGroup
	for _, item := range running {
		cfg := item.server.Config()
		if tunnelReady {
			fmt.Fprintf(c.stdout, "%s proxy listening on %s auth=%t; warp tunnel dialer ready\n", item.spec.Label, item.listener.Addr().String(), cfg.AuthEnabled())
		} else {
			fmt.Fprintf(c.stdout, "%s proxy listening on %s auth=%t\n", item.spec.Label, item.listener.Addr().String(), cfg.AuthEnabled())
		}

		wg.Add(1)
		go func(item runningListener) {
			defer wg.Done()
			if item.spec.HTTP {
				errCh <- item.server.ServeHTTP(serveCtx, item.listener)
				return
			}
			errCh <- item.server.ServeSOCKS5(serveCtx, item.listener)
		}(item)
	}

	go func() {
		wg.Wait()
		close(errCh)
	}()

	var firstErr error
	for err := range errCh {
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
			continue
		}
		if firstErr == nil {
			firstErr = err
			cancel()
			for _, item := range running {
				_ = item.listener.Close()
			}
		}
	}
	if firstErr != nil {
		return firstErr
	}
	fmt.Fprintln(c.stdout, "proxy stopped")
	return nil
}

func (c *Command) loadProxyTunnelConfig(identityPath, endpointValue string, defaults config.Settings) (*warp.Identity, warp.Endpoint, tunnel.Config, error) {
	identity, err := warp.LoadIdentity(identityPath)
	if err != nil {
		return nil, warp.Endpoint{}, tunnel.Config{}, fmt.Errorf("load WARP identity: %w", err)
	}
	endpoint, err := parseSelectedEndpoint(endpointValue, identity.Endpoint)
	if err != nil {
		return nil, warp.Endpoint{}, tunnel.Config{}, err
	}
	return identity, endpoint, tunnel.Config{
		AllowedIPs:          defaults.WireGuard.AllowedIPs,
		DNS:                 defaults.WireGuard.DNS,
		MTU:                 defaults.WireGuard.MTU,
		PersistentKeepalive: defaults.WireGuard.PersistentKeepalive,
	}, nil
}

func parseSelectedEndpoint(selected, identityEndpoint string) (warp.Endpoint, error) {
	raw := strings.TrimSpace(selected)
	if raw == "" {
		raw = strings.TrimSpace(identityEndpoint)
	}
	host, portValue, err := net.SplitHostPort(raw)
	if err != nil {
		return warp.Endpoint{}, fmt.Errorf("selected WARP endpoint must be host:port")
	}
	port, err := strconv.Atoi(portValue)
	if err != nil {
		return warp.Endpoint{}, fmt.Errorf("selected WARP endpoint port must be an integer")
	}
	endpoint, err := warp.NewEndpoint(host, port, warp.TransportUDP)
	if err != nil {
		return warp.Endpoint{}, fmt.Errorf("selected WARP endpoint must be a known Cloudflare WARP IP: %w", err)
	}
	return endpoint, nil
}

func defaultProxyDialerBuilder(ctx context.Context, identity warp.Identity, endpoint warp.Endpoint, cfg tunnel.Config) (proxy.Dialer, error) {
	return tunnel.NewDialer(ctx, identity, endpoint, cfg)
}

func (c *Command) newFlagSet(name string) *flag.FlagSet {
	flags := flag.NewFlagSet("warpshift "+name, flag.ContinueOnError)
	flags.SetOutput(c.stderr)
	return flags
}

func (c *Command) usageError(command string, err error) int {
	fmt.Fprintf(c.stderr, "warpshift %s: unknown flag or invalid arguments: %v\n", command, err)
	return 2
}

func (c *Command) unexpectedArg(command, arg string) int {
	fmt.Fprintf(c.stderr, "warpshift %s: unexpected argument %q\n", command, arg)
	return 2
}

func (c *Command) defaultSnapshot() tui.Snapshot {
	defaults := config.DefaultSettings()
	endpointRows := make([]tui.EndpointSnapshot, 0, len(defaults.Endpoint.Static))
	for _, static := range defaults.Endpoint.Static {
		endpointRows = append(endpointRows, tui.EndpointSnapshot{Address: static + "/udp", Healthy: false, Error: "not scanned"})
	}
	return tui.Snapshot{
		AppName: c.app.Name(),
		Version: c.app.Version(),
		Status: tui.StatusSnapshot{
			WARP:    "unknown",
			Proxy:   "disabled",
			Message: "manual identity import only; live network and tunnel operations are not started by the TUI",
		},
		Endpoints: endpointRows,
	}
}

func parseStaticEndpoints(raw string) ([]warp.Endpoint, error) {
	parts := strings.Split(raw, ",")
	endpoints := make([]warp.Endpoint, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, portValue, err := net.SplitHostPort(part)
		if err != nil {
			return nil, fmt.Errorf("static endpoints must be host:port")
		}
		port, err := strconv.Atoi(portValue)
		if err != nil {
			return nil, fmt.Errorf("static endpoint port must be an integer")
		}
		endpoint, err := warp.NewEndpoint(host, port, warp.TransportUDP)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, endpoint)
	}
	if len(endpoints) == 0 {
		return nil, errors.New("at least one static endpoint is required")
	}
	return endpoints, nil
}

func disabledEndpointProbe(context.Context, warp.Endpoint) (time.Duration, error) {
	return 0, errors.New("live endpoint probing disabled by default")
}

func (c *Command) printHelp() {
	fmt.Fprintf(c.stdout, `%s

Usage: warpshift <command> [options]
       warpshift [--help] [--version]

Commands:
  version                 Show version
  help                    Show help
  tui                     Launch the local Bubble Tea dashboard
  config validate         Validate local TOML configuration
  identity import         Import a manually supplied identity JSON file
  identity inspect        Inspect stored identity metadata without printing keys
  wireguard export        Export a WireGuard profile from a stored manual identity
  trace parse             Parse a local Cloudflare trace fixture
  trace status            Report local trace health from a fixture
  endpoint scan           Scan static endpoints through an injectable probe
  proxy validate          Validate proxy bind/auth configuration
  proxy start             Serve local SOCKS5 and/or HTTP proxy listeners

Safety boundaries:
  - manual identity import only
  - localhost proxy defaults
  - authentication required for remote proxy binds
  - no account registration
  - no WARP+ generation
  - no DPI evasion
  - no streaming unlock
  - no Docker workflows

Foundation scope:
%s
`, c.app.Name(), formatCapabilities(c.app.SafeCapabilities()))
}

func formatCapabilities(capabilities []string) string {
	if len(capabilities) == 0 {
		return "  - none"
	}

	var builder strings.Builder
	for _, capability := range capabilities {
		builder.WriteString("  - ")
		builder.WriteString(capability)
		builder.WriteByte('\n')
	}
	return strings.TrimRight(builder.String(), "\n")
}
