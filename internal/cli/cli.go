package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
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

// TargetProbe checks one streaming/IP rotation candidate. Tests inject this to avoid live network access.
type TargetProbe func(context.Context, warp.StreamingRotationCandidate, []string) warp.StreamingTargetProbeResult

// MTUProbe checks whether one candidate MTU is usable. Tests inject fakes to avoid live probes.
type MTUProbe func(context.Context, int) (bool, error)

// ProxyDialerBuilder constructs the outbound proxy dialer from imported WARP identity material.
type ProxyDialerBuilder func(context.Context, warp.Identity, warp.Endpoint, tunnel.Config) (proxy.Dialer, error)

// Command provides the top-level command-line surface without calling os.Exit.
type Command struct {
	app                *app.App
	stdout             io.Writer
	stderr             io.Writer
	tuiLauncher        TUILauncher
	endpointProbe      EndpointProbe
	targetProbe        TargetProbe
	mtuProbe           MTUProbe
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

// WithTargetProbe injects target probing for streaming/IP rotation run commands.
func WithTargetProbe(probe TargetProbe) Option {
	return func(c *Command) {
		if probe != nil {
			c.targetProbe = probe
		}
	}
}

// WithMTUProbe injects MTU probing for the WireGuard MTU helper.
func WithMTUProbe(probe MTUProbe) Option {
	return func(c *Command) {
		if probe != nil {
			c.mtuProbe = probe
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
		targetProbe:        localTargetProbe,
		mtuProbe:           disabledMTUProbe,
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
	case "profile":
		return c.runProfile(args[1:])
	case "wireguard", "wg":
		return c.runWireGuard(ctx, args[1:])
	case "trace":
		return c.runTrace(args[1:])
	case "endpoint":
		return c.runEndpoint(ctx, args[1:])
	case "rotation":
		return c.runRotation(ctx, args[1:])
	case "proxy":
		return c.runProxy(ctx, args[1:])
	case "account":
		return c.runAccount(ctx, args[1:])
	case "license":
		return c.runLicense(ctx, args[1:])
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
		fmt.Fprintf(c.stdout, "configuration valid: %s (startup=%s, proxy_listen=%s, proxy_allowlist=%s, proxy_rate_limit=%d/min, auto_mtu=%t)\n", *path, settings.App.StartupMode, settings.Proxy.ListenAddress, strings.Join(settings.Proxy.AllowedClientCIDRs, ","), settings.Proxy.RateLimitPerMinute, settings.WireGuard.AutoMTU)
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
			fmt.Fprintln(c.stderr, "warpshift identity import: --input is required for manual identity import")
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

func (c *Command) runProfile(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift profile: expected subcommand import, list, show, switch, or delete")
		return 2
	}
	defaults := config.DefaultSettings()
	switch args[0] {
	case "import":
		flags := c.newFlagSet("profile import")
		name := flags.String("name", "", "profile name")
		input := flags.String("input", "", "manual identity JSON path")
		storeDir := flags.String("store-dir", filepath.Dir(defaults.Identity.StorePath), "profile store directory")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("profile import", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("profile import", flags.Arg(0))
		}
		if strings.TrimSpace(*input) == "" {
			fmt.Fprintln(c.stderr, "warpshift profile import: --input is required")
			return 2
		}
		store, ok := c.openProfileStore("profile import", *storeDir)
		if !ok {
			return 2
		}
		if _, err := store.ImportManualIdentityFile(*name, *input); err != nil {
			fmt.Fprintf(c.stderr, "warpshift profile import: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "profile %s imported\n", *name)
		return 0
	case "list":
		flags := c.newFlagSet("profile list")
		storeDir := flags.String("store-dir", filepath.Dir(defaults.Identity.StorePath), "profile store directory")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("profile list", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("profile list", flags.Arg(0))
		}
		store, ok := c.openProfileStore("profile list", *storeDir)
		if !ok {
			return 2
		}
		profiles, err := store.ListProfiles()
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift profile list: %v\n", err)
			return 2
		}
		if len(profiles) == 0 {
			fmt.Fprintln(c.stdout, "no profiles found")
			return 0
		}
		for _, profile := range profiles {
			marker := " "
			if profile.Active {
				marker = "*"
			}
			fmt.Fprintf(c.stdout, "%s %s endpoint=%s interface_addresses=%d dns=%d\n", marker, profile.Name, profile.Endpoint, profile.InterfaceAddressCount, profile.DNSCount)
		}
		return 0
	case "show":
		flags := c.newFlagSet("profile show")
		name := flags.String("name", "", "profile name")
		storeDir := flags.String("store-dir", filepath.Dir(defaults.Identity.StorePath), "profile store directory")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("profile show", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("profile show", flags.Arg(0))
		}
		store, ok := c.openProfileStore("profile show", *storeDir)
		if !ok {
			return 2
		}
		identity, err := store.LoadProfile(*name)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift profile show: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "profile %s: endpoint=%s interface_addresses=%d dns=%d account_type=%s\n", *name, identity.Endpoint, len(identity.InterfaceAddresses), len(identity.DNS), safeAccountType(identity.AccountType))
		return 0
	case "switch":
		flags := c.newFlagSet("profile switch")
		name := flags.String("name", "", "profile name")
		storeDir := flags.String("store-dir", filepath.Dir(defaults.Identity.StorePath), "profile store directory")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("profile switch", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("profile switch", flags.Arg(0))
		}
		store, ok := c.openProfileStore("profile switch", *storeDir)
		if !ok {
			return 2
		}
		if err := store.SwitchProfile(*name); err != nil {
			fmt.Fprintf(c.stderr, "warpshift profile switch: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "active profile switched to %s\n", *name)
		return 0
	case "delete":
		flags := c.newFlagSet("profile delete")
		name := flags.String("name", "", "profile name")
		storeDir := flags.String("store-dir", filepath.Dir(defaults.Identity.StorePath), "profile store directory")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("profile delete", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("profile delete", flags.Arg(0))
		}
		store, ok := c.openProfileStore("profile delete", *storeDir)
		if !ok {
			return 2
		}
		if err := store.DeleteProfile(*name); err != nil {
			fmt.Fprintf(c.stderr, "warpshift profile delete: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "profile %s deleted\n", *name)
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift profile: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (c *Command) runAccount(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift account: expected subcommand register, status, devices, rename, deactivate, or delete")
		return 2
	}
	defaults := config.DefaultSettings()
	switch args[0] {
	case "register":
		flags := c.newFlagSet("account register")
		configPath := flags.String("config", "configs/warpshift.example.toml", "config file with account_automation consent")
		store := flags.String("store", "", "identity store path; defaults to config identity.store_path")
		baseURL := flags.String("api-base-url", warp.DefaultWARPAPIBaseURL, "WARP API base URL")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("account register", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("account register", flags.Arg(0))
		}
		settings, ok := c.loadAccountConsent("account register", *configPath)
		if !ok {
			return 2
		}
		storePath := strings.TrimSpace(*store)
		if storePath == "" {
			storePath = settings.Identity.StorePath
		}
		client, err := warp.NewAPIClient(warp.APIClientConfig{BaseURL: *baseURL})
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift account register: %v\n", err)
			return 2
		}
		if _, err := warp.RegisterAccount(ctx, warp.AccountRegistrationRequest{Client: client, StorePath: storePath, ExplicitConsent: true, AcknowledgedGate: true}); err != nil {
			fmt.Fprintf(c.stderr, "warpshift account register: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "WARP account registered; identity stored at %s\n", storePath)
		return 0
	case "status", "devices", "delete":
		flags := c.newFlagSet("account " + args[0])
		configPath := flags.String("config", "configs/warpshift.example.toml", "config file with account_automation consent")
		identityPath := flags.String("identity", defaults.Identity.StorePath, "stored WARP identity path")
		baseURL := flags.String("api-base-url", warp.DefaultWARPAPIBaseURL, "WARP API base URL")
		removeLocal := flags.Bool("remove-local", false, "remove local identity after API deregistration")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("account "+args[0], err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("account "+args[0], flags.Arg(0))
		}
		if _, ok := c.loadAccountConsent("account "+args[0], *configPath); !ok {
			return 2
		}
		identity, client, ok := c.loadAPIIdentityAndClient("account "+args[0], *identityPath, *baseURL)
		if !ok {
			return 2
		}
		switch args[0] {
		case "status":
			status, err := client.DeviceStatus(ctx, *identity)
			if err != nil {
				fmt.Fprintf(c.stderr, "warpshift account status: %v\n", err)
				return 2
			}
			fmt.Fprintf(c.stdout, "WARP device status: device_name=%s device_type=%s account_type=%s warp_plus=%t active=%t bound_devices=%d\n", safeDisplayValue(status.DeviceName), safeDisplayValue(status.DeviceType), safeAccountType(status.AccountType), status.WARPPlus, status.Active, len(status.BoundDevices))
			return 0
		case "devices":
			status, err := client.DeviceStatus(ctx, *identity)
			if err != nil {
				fmt.Fprintf(c.stderr, "warpshift account devices: %v\n", err)
				return 2
			}
			if len(status.BoundDevices) == 0 {
				fmt.Fprintln(c.stdout, "no bound devices reported by account status response")
				return 0
			}
			fmt.Fprintf(c.stdout, "bound devices: count=%d\n", len(status.BoundDevices))
			for i, device := range status.BoundDevices {
				fmt.Fprintf(c.stdout, "device %d: name=%s type=%s active=%t current=%t\n", i+1, safeDisplayValue(device.Name), safeDisplayValue(device.DeviceType), device.Active, device.Current)
			}
			return 0
		}
		if err := client.DeleteDevice(ctx, *identity); err != nil {
			fmt.Fprintf(c.stderr, "warpshift account delete: %v\n", err)
			return 2
		}
		fmt.Fprintln(c.stdout, "WARP device deregistered")
		if *removeLocal {
			if err := os.Remove(*identityPath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(c.stderr, "warpshift account delete: remove local identity failed: %v\n", err)
				return 2
			}
			fmt.Fprintln(c.stdout, "local identity removed")
		}
		return 0
	case "rename", "deactivate":
		flags := c.newFlagSet("account " + args[0])
		configPath := flags.String("config", "configs/warpshift.example.toml", "config file with account_automation consent")
		name := flags.String("name", "", "new device name for account rename")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("account "+args[0], err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("account "+args[0], flags.Arg(0))
		}
		if _, ok := c.loadAccountConsent("account "+args[0], *configPath); !ok {
			return 2
		}
		var err error
		if args[0] == "rename" {
			err = warp.RenameDevice(ctx, warp.DeviceOperationRequest{Name: *name, ExplicitConsent: true, AcknowledgedGate: true})
		} else {
			err = warp.DeactivateDevice(ctx, warp.DeviceOperationRequest{ExplicitConsent: true, AcknowledgedGate: true})
		}
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift account %s: %v; use account delete only for explicit API deregistration\n", args[0], err)
			return 2
		}
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift account: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (c *Command) runLicense(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift license: expected subcommand bind or status")
		return 2
	}
	if args[0] != "bind" && args[0] != "status" {
		fmt.Fprintf(c.stderr, "warpshift license: unknown subcommand %q\n", args[0])
		return 2
	}
	defaults := config.DefaultSettings()
	flags := c.newFlagSet("license " + args[0])
	configPath := flags.String("config", "configs/warpshift.example.toml", "config file with warp_plus_generation consent")
	identityPath := flags.String("identity", defaults.Identity.StorePath, "stored WARP identity path")
	baseURL := flags.String("api-base-url", warp.DefaultWARPAPIBaseURL, "WARP API base URL")
	licenseKey := flags.String("license-key", "", "user-owned WARP+ license key for bind")
	if err := flags.Parse(args[1:]); err != nil {
		return c.usageError("license "+args[0], err)
	}
	if flags.NArg() != 0 {
		return c.unexpectedArg("license "+args[0], flags.Arg(0))
	}
	if _, ok := c.loadWARPPlusConsent("license "+args[0], *configPath); !ok {
		return 2
	}
	identity, client, ok := c.loadAPIIdentityAndClient("license "+args[0], *identityPath, *baseURL)
	if !ok {
		return 2
	}
	if args[0] == "status" {
		status, err := client.DeviceStatus(ctx, *identity)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift license status: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "WARP+ status: warp_plus=%t account_type=%s\n", status.WARPPlus, safeAccountType(status.AccountType))
		return 0
	}
	status, err := warp.BindOfficialLicenseToDevice(ctx, warp.OfficialLicenseAPIRequest{Client: client, Identity: *identity, LicenseKey: *licenseKey, ExplicitConsent: true, AcknowledgedGate: true})
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift license bind: %v\n", err)
		return 2
	}
	fmt.Fprintf(c.stdout, "WARP+ license bound: warp_plus=%t account_type=%s\n", status.WARPPlus, safeAccountType(status.AccountType))
	return 0
}

func (c *Command) runWireGuard(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift wireguard: expected subcommand export or mtu")
		return 2
	}
	defaultMTU := tunnel.DefaultMTUDetectionConfig()
	switch args[0] {
	case "export":
		defaults := config.DefaultSettings()
		flags := c.newFlagSet("wireguard export")
		identityPath := flags.String("identity", defaults.Identity.StorePath, "identity store path")
		output := flags.String("output", defaults.WireGuard.OutputPath, "WireGuard profile output path")
		endpoint := flags.String("endpoint", defaults.WireGuard.Endpoint, "WireGuard peer endpoint")
		mtu := flags.Int("mtu", defaults.WireGuard.MTU, "WireGuard MTU; use wireguard mtu for injected auto-detection guidance")
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
			MTU:                 *mtu,
			PersistentKeepalive: defaults.WireGuard.PersistentKeepalive,
		}
		if err := warp.ExportWireGuardProfile(*output, *identity, profile); err != nil {
			fmt.Fprintf(c.stderr, "warpshift wireguard export: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "WireGuard profile exported to %s\n", *output)
		return 0
	case "mtu":
		flags := c.newFlagSet("wireguard mtu")
		minMTU := flags.Int("min", defaultMTU.Min, "minimum MTU candidate")
		maxMTU := flags.Int("max", defaultMTU.Max, "maximum MTU candidate")
		step := flags.Int("step", defaultMTU.Step, "bounded MTU decrement step")
		fallback := flags.Int("default", defaultMTU.Default, "fallback MTU when probes do not accept a candidate")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("wireguard mtu", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("wireguard mtu", flags.Arg(0))
		}
		mtu, result, err := tunnel.DetectMTU(ctx, tunnel.MTUDetectionConfig{Min: *minMTU, Max: *maxMTU, Step: *step, Default: *fallback}, tunnel.MTUProbe(c.mtuProbe))
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift wireguard mtu: %v\n", err)
			return 2
		}
		fmt.Fprintf(c.stdout, "mtu recommendation: mtu=%d probed=%t attempts=%d error=%s\n", mtu, result.ProbedOK, result.Attempts, result.Error)
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift wireguard: unknown subcommand %q\n", args[0])
		return 2
	}
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
		fmt.Fprintf(c.stderr, "warpshift trace %s: --file is required for trace input\n", args[0])
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
		fmt.Fprintln(c.stderr, "warpshift endpoint: expected subcommand scan or pool")
		return 2
	}
	switch args[0] {
	case "scan":
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
	case "pool":
		flags := c.newFlagSet("endpoint pool")
		maxPerPrefix := flags.Int("max-per-prefix", 1, "maximum deterministic endpoints to generate per compact WARP prefix")
		includeIPv6 := flags.Bool("ipv6", false, "include compact IPv6 WARP endpoint ranges")
		portValues := flags.String("port", "2408", "comma-separated UDP ports to include")
		labelFilter := flags.String("label", "", "optional comma-separated labels to require")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("endpoint pool", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("endpoint pool", flags.Arg(0))
		}
		ports, err := parsePortList(*portValues)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift endpoint pool: %v\n", err)
			return 2
		}
		entries, err := warp.ExpandKnownWARPEndpointPool(warp.EndpointPoolSpec{Ports: ports, MaxPerPrefix: *maxPerPrefix, IncludeIPv4: true, IncludeIPv6: *includeIPv6})
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift endpoint pool: %v\n", err)
			return 2
		}
		entries = warp.FilterEndpointPool(entries, warp.EndpointPoolFilter{Labels: splitCSV(*labelFilter)})
		for _, entry := range entries {
			fmt.Fprintf(c.stdout, "%s/%s labels=%s\n", formatEndpointAddress(entry.Endpoint), entry.Endpoint.Transport, strings.Join(entry.Labels, ","))
		}
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift endpoint: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (c *Command) runRotation(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift rotation: expected subcommand inspect, plan, run, or report")
		return 2
	}
	switch args[0] {
	case "inspect":
		flags := c.newFlagSet("rotation inspect")
		configPath := flags.String("config", "configs/warpshift.example.toml", "config file path")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("rotation inspect", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("rotation inspect", flags.Arg(0))
		}
		settings, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift rotation inspect: %v\n", err)
			return 2
		}
		rotation := settings.Rotation
		fmt.Fprintf(c.stdout, "rotation policy: strategies=%s failure_threshold=%d timed_interval=%ds max_latency_ms=%d max_attempts=%d cooldown=%ds history=%s target_labels=%s region_labels=%s\n", strings.Join(rotation.Strategies, ","), rotation.FailureThreshold, rotation.TimedIntervalSeconds, rotation.MaxLatencyMS, rotation.MaxAttempts, rotation.CooldownSeconds, rotation.HistoryPath, strings.Join(rotation.TargetLabels, ","), strings.Join(rotation.RegionLabels, ","))
		fmt.Fprintln(c.stdout, "rotation planner/report use local planning data; run requires streaming unlock consent and uses an injected/local target probe")
		return 0
	case "plan":
		flags := c.newFlagSet("rotation plan")
		configPath := flags.String("config", "configs/warpshift.example.toml", "config file path")
		historyPath := flags.String("history", "", "optional rotation history JSON path for cooldown/backoff")
		targetLabels := flags.String("target-label", "", "optional comma-separated target labels to require")
		maxCandidates := flags.Int("max-candidates", 0, "maximum candidates to display; defaults to config rotation.max_attempts")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("rotation plan", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("rotation plan", flags.Arg(0))
		}
		loaded, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift rotation plan: %v\n", err)
			return 2
		}
		if strings.TrimSpace(*historyPath) != "" {
			loaded.Rotation.HistoryPath = *historyPath
		}
		settings, plan, ok := c.buildRotationPlan("rotation plan", *configPath, *targetLabels, *maxCandidates, &loaded)
		if !ok {
			return 2
		}
		c.printRotationPlan(plan, settings.Rotation.MaxAttempts)
		return 0
	case "run":
		flags := c.newFlagSet("rotation run")
		configPath := flags.String("config", "configs/warpshift.example.toml", "config file with streaming unlock consent")
		historyPath := flags.String("history", "", "rotation history JSON path; defaults to config rotation.history_path")
		targetLabels := flags.String("target-label", "", "optional comma-separated target labels to require")
		maxAttempts := flags.Int("max-attempts", 0, "maximum target-check attempts; defaults to config rotation.max_attempts")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("rotation run", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("rotation run", flags.Arg(0))
		}
		settings, ok := c.loadStreamingConsent("rotation run", *configPath)
		if !ok {
			return 2
		}
		if strings.TrimSpace(*historyPath) != "" {
			settings.Rotation.HistoryPath = *historyPath
		}
		attempts := *maxAttempts
		if attempts <= 0 {
			attempts = settings.Rotation.MaxAttempts
		}
		_, plan, ok := c.buildRotationPlan("rotation run", *configPath, *targetLabels, attempts, &settings)
		if !ok {
			return 2
		}
		executor, err := warp.NewStreamingRotationExecutor(warp.StreamingTargetProbe(c.targetProbe))
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift rotation run: %v\n", err)
			return 2
		}
		run, err := executor.Run(ctx, plan, warp.StreamingRotationRunOptions{MaxAttempts: attempts})
		if len(run.Attempts) > 0 {
			storePath := settings.Rotation.HistoryPath
			store, storeErr := warp.NewStreamingRotationHistoryStore(storePath)
			if storeErr != nil {
				fmt.Fprintf(c.stderr, "warpshift rotation run: %v\n", storeErr)
				return 2
			}
			if storeErr := store.Append(run.Attempts...); storeErr != nil {
				fmt.Fprintf(c.stderr, "warpshift rotation run: %v\n", storeErr)
				return 2
			}
		}
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift rotation run: %v\n", err)
			return 1
		}
		fmt.Fprintf(c.stdout, "rotation run selected: endpoint=%s profile=%s target_ok=%t latency_ms=%d attempts=%d\n", run.Selected.Endpoint, safeProfileName(run.Selected.ProfileName), run.Selected.TargetOK, run.Selected.LatencyMS, len(run.Attempts))
		return 0
	case "report":
		flags := c.newFlagSet("rotation report")
		historyPath := flags.String("history", config.DefaultSettings().Rotation.HistoryPath, "rotation history JSON path")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("rotation report", err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("rotation report", flags.Arg(0))
		}
		store, err := warp.NewStreamingRotationHistoryStore(*historyPath)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift rotation report: %v\n", err)
			return 2
		}
		history, err := store.Load()
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift rotation report: %v\n", err)
			return 2
		}
		if len(history) == 0 {
			fmt.Fprintln(c.stdout, "no rotation history found")
			return 0
		}
		fmt.Fprintf(c.stdout, "rotation history: entries=%d\n", len(history))
		for _, result := range history {
			fmt.Fprintf(c.stdout, "%s endpoint=%s profile=%s target_ok=%t healthy=%t latency_ms=%d error=%s\n", result.CheckedAt.Format(time.RFC3339), result.Endpoint, safeProfileName(result.ProfileName), result.TargetOK, result.Healthy, result.LatencyMS, result.Error)
		}
		return 0
	default:
		fmt.Fprintf(c.stderr, "warpshift rotation: unknown subcommand %q\n", args[0])
		return 2
	}
}

func (c *Command) runProxy(ctx context.Context, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "warpshift proxy: expected subcommand validate or start")
		return 2
	}
	switch args[0] {
	case "validate", "start":
		defaults := config.DefaultSettings()
		settings := defaults
		flags := c.newFlagSet("proxy " + args[0])
		configPath := flags.String("config", "", "optional TOML config path; proxy.enabled=false disables the configured proxy")
		listen := flags.String("listen", proxy.DefaultListenAddr, "proxy listen address; used for SOCKS5 unless --socks-listen/--http-listen selects listeners")
		socksListen := flags.String("socks-listen", "", "SOCKS5 proxy listen address")
		httpListen := flags.String("http-listen", "", "HTTP proxy listen address")
		username := flags.String("username", "", "proxy username")
		password := flags.String("password", "", "proxy password")
		identityPath := flags.String("identity", "", "stored WARP WireGuard identity path")
		endpointValue := flags.String("endpoint", "", "selected WARP endpoint host:port")
		allowCIDRs := flags.String("allow-cidr", strings.Join(defaults.Proxy.AllowedClientCIDRs, ","), "comma-separated client CIDRs allowed to use the proxy")
		rateLimitPerMinute := flags.Int("rate-limit-per-minute", defaults.Proxy.RateLimitPerMinute, "per-client proxy connection rate limit per minute")
		rateLimitBurst := flags.Int("rate-limit-burst", defaults.Proxy.RateLimitBurst, "per-client proxy connection burst")
		if err := flags.Parse(args[1:]); err != nil {
			return c.usageError("proxy "+args[0], err)
		}
		if flags.NArg() != 0 {
			return c.unexpectedArg("proxy "+args[0], flags.Arg(0))
		}
		setFlags := map[string]bool{}
		flags.Visit(func(flag *flag.Flag) { setFlags[flag.Name] = true })

		configLoaded := strings.TrimSpace(*configPath) != ""
		if configLoaded {
			loaded, err := config.Load(*configPath)
			if err != nil {
				fmt.Fprintf(c.stderr, "warpshift proxy %s: %v\n", args[0], err)
				return 2
			}
			settings = loaded
			if !settings.Proxy.Enabled {
				fmt.Fprintf(c.stdout, "proxy disabled by config: %s\n", *configPath)
				return 0
			}
			if !setFlags["listen"] {
				*listen = settings.Proxy.ListenAddress
			}
			if !setFlags["allow-cidr"] {
				*allowCIDRs = strings.Join(settings.Proxy.AllowedClientCIDRs, ",")
			}
			if !setFlags["rate-limit-per-minute"] {
				*rateLimitPerMinute = settings.Proxy.RateLimitPerMinute
			}
			if !setFlags["rate-limit-burst"] {
				*rateLimitBurst = settings.Proxy.RateLimitBurst
			}
		}

		listeners := selectedProxyListeners(flags, *listen, *socksListen, *httpListen)
		if len(listeners) == 0 {
			fmt.Fprintf(c.stderr, "warpshift proxy %s: at least one proxy listener is required\n", args[0])
			return 2
		}

		baseConfig := proxy.Config{Username: *username, Password: *password, AllowedClientCIDRs: splitCSV(*allowCIDRs), RateLimitPerMinute: *rateLimitPerMinute, RateLimitBurst: *rateLimitBurst}
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
			identity, endpoint, tunnelConfig, err := c.loadProxyTunnelConfig(*identityPath, *endpointValue, settings)
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
				fmt.Fprintf(c.stdout, "proxy configuration valid: listen=%s auth=%t listeners=%d allowlist=%s rate_limit=%d/min burst=%d; warp tunnel configuration valid\n", firstConfig.ListenAddr, firstConfig.AuthEnabled(), len(listeners), strings.Join(firstConfig.AllowedClientCIDRs, ","), firstConfig.RateLimitPerMinute, firstConfig.RateLimitBurst)
				return 0
			}
			fmt.Fprintf(c.stdout, "proxy configuration valid: listen=%s auth=%t listeners=%d allowlist=%s rate_limit=%d/min burst=%d\n", firstConfig.ListenAddr, firstConfig.AuthEnabled(), len(listeners), strings.Join(firstConfig.AllowedClientCIDRs, ","), firstConfig.RateLimitPerMinute, firstConfig.RateLimitBurst)
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
			fmt.Fprintf(c.stdout, "%s proxy listening on %s auth=%t allowlist=%s rate_limit=%d/min burst=%d; warp tunnel dialer ready\n", item.spec.Label, item.listener.Addr().String(), cfg.AuthEnabled(), strings.Join(cfg.AllowedClientCIDRs, ","), cfg.RateLimitPerMinute, cfg.RateLimitBurst)
		} else {
			fmt.Fprintf(c.stdout, "%s proxy listening on %s auth=%t allowlist=%s rate_limit=%d/min burst=%d\n", item.spec.Label, item.listener.Addr().String(), cfg.AuthEnabled(), strings.Join(cfg.AllowedClientCIDRs, ","), cfg.RateLimitPerMinute, cfg.RateLimitBurst)
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

func (c *Command) loadAccountConsent(command, path string) (config.Settings, bool) {
	settings, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, false
	}
	if !settings.Safety.AccountAutomation || !settings.Safety.AccountAutomationConsent {
		fmt.Fprintf(c.stderr, "warpshift %s: safety.account_automation and safety.account_automation_consent are required for private-use WARP account automation\n", command)
		return config.Settings{}, false
	}
	return settings, true
}

func (c *Command) loadWARPPlusConsent(command, path string) (config.Settings, bool) {
	settings, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, false
	}
	if !settings.Safety.WARPPlusGeneration || !settings.Safety.WARPPlusGenerationConsent {
		fmt.Fprintf(c.stderr, "warpshift %s: safety.warp_plus_generation and safety.warp_plus_generation_consent are required for private-use WARP+ license workflows\n", command)
		return config.Settings{}, false
	}
	return settings, true
}

func (c *Command) loadStreamingConsent(command, path string) (config.Settings, bool) {
	settings, err := config.Load(path)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, false
	}
	if !settings.Safety.StreamingUnlock || !settings.Safety.StreamingUnlockConsent {
		fmt.Fprintf(c.stderr, "warpshift %s: safety.streaming_unlock and safety.streaming_unlock_consent are required for private-use streaming/IP rotation runs\n", command)
		return config.Settings{}, false
	}
	return settings, true
}

func (c *Command) buildRotationPlan(command, configPath, targetLabelCSV string, maxCandidates int, loaded *config.Settings) (config.Settings, warp.StreamingRotationPlan, bool) {
	settings := config.Settings{}
	if loaded != nil {
		settings = *loaded
	} else {
		var err error
		settings, err = config.Load(configPath)
		if err != nil {
			fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
			return config.Settings{}, warp.StreamingRotationPlan{}, false
		}
	}

	entries, err := rotationEndpointEntries(settings)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, warp.StreamingRotationPlan{}, false
	}
	profiles, err := rotationProfileSummaries(filepath.Dir(settings.Identity.StorePath))
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, warp.StreamingRotationPlan{}, false
	}
	history, err := rotationHistory(settings.Rotation.HistoryPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, warp.StreamingRotationPlan{}, false
	}

	limit := maxCandidates
	if limit <= 0 {
		limit = settings.Rotation.MaxAttempts
	}
	planner := warp.NewStreamingRotationPlanner()
	plan, err := planner.Plan(warp.StreamingRotationPlanRequest{
		Policy:        rotationPolicyFromSettings(settings.Rotation),
		EndpointPool:  entries,
		Profiles:      profiles,
		History:       history,
		TargetLabels:  splitCSV(targetLabelCSV),
		Cooldown:      time.Duration(settings.Rotation.CooldownSeconds) * time.Second,
		BackoffBase:   time.Duration(settings.Rotation.CooldownSeconds) * time.Second,
		MaxCandidates: limit,
	})
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return config.Settings{}, warp.StreamingRotationPlan{}, false
	}
	return settings, plan, true
}

func (c *Command) printRotationPlan(plan warp.StreamingRotationPlan, defaultAttempts int) {
	fmt.Fprintf(c.stdout, "rotation plan: generated=%s candidates=%d skipped=%d\n", plan.GeneratedAt.Format(time.RFC3339), len(plan.Candidates), len(plan.Skipped))
	for i, candidate := range plan.Candidates {
		fmt.Fprintf(c.stdout, "candidate %d: endpoint=%s profile=%s active_profile=%t failures=%d latency_ms=%d labels=%s\n", i+1, candidate.Endpoint.String(), safeProfileName(candidate.ProfileName), candidate.ActiveProfile, candidate.FailureCount, candidate.LastLatencyMS, strings.Join(candidate.Labels, ","))
	}
	if len(plan.Candidates) == 0 {
		fmt.Fprintf(c.stdout, "no rotation candidates available within max_attempts=%d\n", defaultAttempts)
	}
}

func rotationPolicyFromSettings(settings config.RotationSettings) warp.RotationPolicy {
	strategies := make([]warp.RotationStrategy, 0, len(settings.Strategies))
	for _, strategy := range settings.Strategies {
		strategies = append(strategies, warp.RotationStrategy(strategy))
	}
	return warp.RotationPolicy{
		Strategies:       strategies,
		FailureThreshold: settings.FailureThreshold,
		TimedInterval:    time.Duration(settings.TimedIntervalSeconds) * time.Second,
		MaxLatency:       time.Duration(settings.MaxLatencyMS) * time.Millisecond,
		TargetLabels:     append([]string(nil), settings.TargetLabels...),
		RegionLabels:     append([]string(nil), settings.RegionLabels...),
	}
}

func rotationEndpointEntries(settings config.Settings) ([]warp.EndpointPoolEntry, error) {
	endpoints, err := parseStaticEndpoints(strings.Join(settings.Endpoint.Static, ","))
	if err != nil {
		return nil, err
	}
	entries := make([]warp.EndpointPoolEntry, 0, len(endpoints))
	for _, endpoint := range endpoints {
		family := "ipv4"
		if strings.Contains(endpoint.Address, ":") {
			family = "ipv6"
		}
		entries = append(entries, warp.EndpointPoolEntry{Endpoint: endpoint, Labels: []string{"cloudflare-warp", "general", "global", "static", family}})
	}
	return entries, nil
}

func rotationProfileSummaries(storeDir string) ([]warp.ProfileSummary, error) {
	if _, err := os.Stat(storeDir); os.IsNotExist(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("stat profile store: %w", err)
	}
	store, err := warp.NewProfileStore(storeDir)
	if err != nil {
		return nil, err
	}
	return store.ListProfiles()
}

func rotationHistory(path string) ([]warp.StreamingRotationResult, error) {
	store, err := warp.NewStreamingRotationHistoryStore(path)
	if err != nil {
		return nil, err
	}
	return store.Load()
}

func (c *Command) loadAPIIdentityAndClient(command, identityPath, baseURL string) (*warp.Identity, *warp.APIClient, bool) {
	identity, err := warp.LoadIdentity(identityPath)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return nil, nil, false
	}
	client, err := warp.NewAPIClient(warp.APIClientConfig{BaseURL: baseURL})
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return nil, nil, false
	}
	return identity, client, true
}

func safeDisplayValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func safeAccountType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func safeProfileName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "none"
	}
	return value
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
			Message: "manual identity import available; live network and tunnel operations require explicit command action",
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

func (c *Command) openProfileStore(command, storeDir string) (*warp.ProfileStore, bool) {
	store, err := warp.NewProfileStore(storeDir)
	if err != nil {
		fmt.Fprintf(c.stderr, "warpshift %s: %v\n", command, err)
		return nil, false
	}
	return store, true
}

func parsePortList(raw string) ([]int, error) {
	parts := splitCSV(raw)
	if len(parts) == 0 {
		return nil, errors.New("at least one endpoint pool port is required")
	}
	ports := make([]int, 0, len(parts))
	for _, part := range parts {
		port, err := strconv.Atoi(part)
		if err != nil || port <= 0 || port > 65535 {
			return nil, fmt.Errorf("endpoint pool ports must be integers between 1 and 65535")
		}
		ports = append(ports, port)
	}
	return ports, nil
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	values := []string{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func formatEndpointAddress(endpoint warp.Endpoint) string {
	return net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port))
}

func disabledEndpointProbe(context.Context, warp.Endpoint) (time.Duration, error) {
	return 0, errors.New("endpoint probing requires an injected probe")
}

func disabledMTUProbe(context.Context, int) (bool, error) {
	return false, nil
}

func localTargetProbe(context.Context, warp.StreamingRotationCandidate, []string) warp.StreamingTargetProbeResult {
	return warp.StreamingTargetProbeResult{OK: true}
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
  profile import          Import a manual identity into a named local profile
  profile list            List named profiles without printing keys
  profile show            Show safe metadata for one profile
  profile switch          Select the active local profile
  profile delete          Delete one named local profile
  wireguard export        Export a WireGuard profile from a stored manual identity
  wireguard mtu           Recommend MTU through bounded injected probes
  trace parse             Parse a local Cloudflare trace fixture
  trace status            Report local trace health from a fixture
  endpoint scan           Scan static endpoints through an injectable probe
  endpoint pool           Expand compact known WARP ranges into a bounded local pool
  rotation inspect        Inspect rotation policy
  rotation plan           Plan bounded local streaming/IP rotation candidates
  rotation run            Run consent-gated streaming/IP rotation checks
  rotation report         Report local secret-safe rotation history
  proxy validate          Validate proxy bind/auth configuration
  proxy start             Serve local SOCKS5 and/or HTTP proxy listeners
  account register        Register and securely store a private-use WARP identity
  account status          Fetch account/device status (device metadata may be displayed; no private keys or tokens are printed)
  account devices         List bound devices reported by account status responses
  account rename          Report unsupported device naming semantics without network calls
  account deactivate      Report unsupported soft-deactivation semantics without network calls
  account delete          Deregister a device and optionally remove local identity
  license bind            Bind a user-owned WARP+ license with explicit consent
  license status          Fetch WARP+ status without printing license material

Safety boundaries:
  - manual identity import remains available as a consent-free local path
  - profile storage uses named local identities
  - endpoint pool expansion is deterministic and local-first
  - rotation plan/report are local-first; rotation run requires safety.streaming_unlock_consent
  - account automation requires safety.account_automation_consent
  - WARP+ license workflows require safety.warp_plus_generation_consent
  - DPI-related workflows require explicit user consent when implemented
  - localhost proxy defaults
  - authentication required for remote proxy binds
  - proxy allowlisting and rate limiting
  - WireGuard MTU helper uses injected probes
  - users are responsible for enabled private-use workflows

Capability scope:
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
