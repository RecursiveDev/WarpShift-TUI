package warp

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const DefaultWARPAPIBaseURL = "https://api.cloudflareclient.com/v0a2158"

// ErrAccountAutomationConsentRequired is returned before account/device API workflows run without explicit private-use consent.
var ErrAccountAutomationConsentRequired = errors.New("explicit private-use consent is required for WARP account automation")

// ErrUnsupportedAccountOperation is returned for account operations whose Cloudflare API semantics are not safely bounded yet.
var ErrUnsupportedAccountOperation = errors.New("WARP account operation is not implemented in this version")

// APIClientConfig configures a WARP API client. Tests should inject BaseURL and HTTPClient.
type APIClientConfig struct {
	BaseURL    string
	HTTPClient *http.Client
	UserAgent  string
}

// APIClient is a small Cloudflare WARP API client with injectable transport and base URL.
type APIClient struct {
	baseURL    *url.URL
	httpClient *http.Client
	userAgent  string
}

// NewAPIClient creates a client. With zero config it targets the official WARP API base URL.
func NewAPIClient(config APIClientConfig) (*APIClient, error) {
	baseURL := strings.TrimSpace(config.BaseURL)
	if baseURL == "" {
		baseURL = DefaultWARPAPIBaseURL
	}
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("warp api base url must be an absolute URL")
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	userAgent := strings.TrimSpace(config.UserAgent)
	if userAgent == "" {
		userAgent = "WarpShift-TUI"
	}
	return &APIClient{baseURL: parsed, httpClient: httpClient, userAgent: userAgent}, nil
}

// AccountRegistrationRequest describes a consent-gated registration and secure local store operation.
type AccountRegistrationRequest struct {
	Client           *APIClient
	StorePath        string
	ExplicitConsent  bool
	AcknowledgedGate bool
}

// RegisterAccount registers a user-controlled WARP device and stores the returned identity securely.
func RegisterAccount(ctx context.Context, request AccountRegistrationRequest) (*Identity, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !request.ExplicitConsent || !request.AcknowledgedGate {
		return nil, ErrAccountAutomationConsentRequired
	}
	if request.Client == nil {
		return nil, errors.New("warp api client is required")
	}
	if strings.TrimSpace(request.StorePath) == "" {
		return nil, errors.New("identity store path is required")
	}
	privateKey, publicKey, err := generateWireGuardKeyPair()
	if err != nil {
		return nil, err
	}
	identity, err := request.Client.RegisterDevice(ctx, publicKey, privateKey)
	if err != nil {
		return nil, err
	}
	if err := SaveIdentity(request.StorePath, *identity); err != nil {
		return nil, err
	}
	return identity, nil
}

// DeviceStatus is sanitized account/device status metadata returned by the WARP API client.
type DeviceStatus struct {
	DeviceID     string
	DeviceName   string
	DeviceType   string
	AccountID    string
	AccountType  string
	WARPPlus     bool
	Active       bool
	BoundDevices []BoundDevice
}

// BoundDevice is sanitized metadata for a device listed in an account status response.
type BoundDevice struct {
	DeviceID   string
	Name       string
	DeviceType string
	Active     bool
	Current    bool
}

// DeviceOperationRequest describes consent-gated device management operations.
type DeviceOperationRequest struct {
	Client           *APIClient
	Identity         Identity
	Name             string
	ExplicitConsent  bool
	AcknowledgedGate bool
}

// OfficialLicenseAPIRequest describes consent-gated official WARP+ license binding via the API client.
type OfficialLicenseAPIRequest struct {
	Client           *APIClient
	Identity         Identity
	LicenseKey       string
	ExplicitConsent  bool
	AcknowledgedGate bool
}

// BindOfficialLicenseToDevice binds a user-owned WARP+ license to a registered local identity.
func BindOfficialLicenseToDevice(ctx context.Context, request OfficialLicenseAPIRequest) (*DeviceStatus, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !request.ExplicitConsent || !request.AcknowledgedGate {
		return nil, ErrOfficialLicenseConsentRequired
	}
	if strings.TrimSpace(request.LicenseKey) == "" {
		return nil, errors.New("official license key is required")
	}
	if request.Client == nil {
		return nil, errors.New("warp api client is required")
	}
	if err := validateIdentity(request.Identity); err != nil {
		return nil, err
	}
	return request.Client.BindLicense(ctx, request.Identity, request.LicenseKey)
}

// RegisterDevice performs only the WARP API registration call; callers own consent and storage.
func (c *APIClient) RegisterDevice(ctx context.Context, publicKey, privateKey string) (*Identity, error) {
	installID, err := randomInstallID()
	if err != nil {
		return nil, err
	}
	body := map[string]string{
		"key":        strings.TrimSpace(publicKey),
		"install_id": installID,
		"fcm_token":  "",
		"tos":        time.Now().UTC().Format(time.RFC3339),
		"type":       "Android",
		"locale":     "en_US",
	}
	var response apiDeviceResponse
	if err := c.doJSON(ctx, http.MethodPost, "register device", "/reg", "", body, &response); err != nil {
		return nil, err
	}
	return response.toIdentity(privateKey)
}

// DeviceStatus fetches account/device status for a stored identity.
func (c *APIClient) DeviceStatus(ctx context.Context, identity Identity) (*DeviceStatus, error) {
	if err := requireDeviceCredentials(identity); err != nil {
		return nil, err
	}
	var response apiDeviceResponse
	if err := c.doJSON(ctx, http.MethodGet, "device status", "/reg/"+url.PathEscape(identity.DeviceID), identity.Token, nil, &response); err != nil {
		return nil, err
	}
	return response.toStatus(), nil
}

// BindLicense binds a user-owned official license to the account associated with identity.
func (c *APIClient) BindLicense(ctx context.Context, identity Identity, licenseKey string) (*DeviceStatus, error) {
	if err := requireDeviceCredentials(identity); err != nil {
		return nil, err
	}
	body := map[string]string{"license": strings.TrimSpace(licenseKey)}
	var response apiDeviceResponse
	if err := c.doJSON(ctx, http.MethodPatch, "license binding", "/reg/"+url.PathEscape(identity.DeviceID)+"/account", identity.Token, body, &response); err != nil {
		return nil, err
	}
	return response.toStatus(), nil
}

// RenameDevice is intentionally unsupported until Cloudflare WARP device naming API semantics are safely bounded.
func RenameDevice(ctx context.Context, request DeviceOperationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.ExplicitConsent || !request.AcknowledgedGate {
		return ErrAccountAutomationConsentRequired
	}
	if strings.TrimSpace(request.Name) == "" {
		return errors.New("device name is required")
	}
	return ErrUnsupportedAccountOperation
}

// DeactivateDevice is intentionally unsupported until Cloudflare WARP soft-deactivation API semantics are safely bounded.
func DeactivateDevice(ctx context.Context, request DeviceOperationRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.ExplicitConsent || !request.AcknowledgedGate {
		return ErrAccountAutomationConsentRequired
	}
	return ErrUnsupportedAccountOperation
}

// DeleteDevice deregisters a stored identity from the WARP API.
func (c *APIClient) DeleteDevice(ctx context.Context, identity Identity) error {
	if err := requireDeviceCredentials(identity); err != nil {
		return err
	}
	return c.doJSON(ctx, http.MethodDelete, "device deletion", "/reg/"+url.PathEscape(identity.DeviceID), identity.Token, nil, nil)
}

func (c *APIClient) doJSON(ctx context.Context, method, operation, endpoint, token string, payload any, target any) error {
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("warp api %s payload invalid", operation)
		}
		body = bytes.NewReader(encoded)
	}
	requestURL := c.resolve(endpoint)
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return fmt.Errorf("warp api %s request invalid", operation)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return fmt.Errorf("warp api %s request failed", operation)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("warp api %s failed: status %d", operation, resp.StatusCode)
	}
	if target == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		return nil
	}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("warp api %s response invalid", operation)
	}
	return nil
}

func (c *APIClient) resolve(endpoint string) string {
	resolved := *c.baseURL
	basePath := strings.TrimRight(resolved.Path, "/")
	endpointPath := "/" + strings.TrimLeft(endpoint, "/")
	resolved.Path = path.Clean(basePath + endpointPath)
	return resolved.String()
}

func requireDeviceCredentials(identity Identity) error {
	if strings.TrimSpace(identity.DeviceID) == "" {
		return errors.New("stored identity is missing device metadata")
	}
	if strings.TrimSpace(identity.Token) == "" {
		return errors.New("stored identity is missing API token metadata")
	}
	return nil
}

func generateWireGuardKeyPair() (privateKey string, publicKey string, err error) {
	privateBytes := make([]byte, 32)
	if _, err := rand.Read(privateBytes); err != nil {
		return "", "", errors.New("generate wireguard key failed")
	}
	privateBytes[0] &= 248
	privateBytes[31] &= 127
	privateBytes[31] |= 64
	curve := ecdh.X25519()
	key, err := curve.NewPrivateKey(privateBytes)
	if err != nil {
		return "", "", errors.New("generate wireguard key failed")
	}
	return base64.StdEncoding.EncodeToString(privateBytes), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

var installIDRandomReader io.Reader = rand.Reader

func randomInstallID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := io.ReadFull(installIDRandomReader, bytes); err != nil {
		return "", fmt.Errorf("generate install id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

type apiDeviceResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Active  *bool  `json:"active"`
	Enabled *bool  `json:"enabled"`
	Token   string `json:"token"`
	Account struct {
		ID          string                     `json:"id"`
		AccountType string                     `json:"account_type"`
		License     string                     `json:"license"`
		Devices     []apiAccountDeviceResponse `json:"devices"`
	} `json:"account"`
	Config struct {
		ClientID  string `json:"client_id"`
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				Host string `json:"host"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

type apiAccountDeviceResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	Active  *bool  `json:"active"`
	Enabled *bool  `json:"enabled"`
}

func (r apiDeviceResponse) toIdentity(privateKey string) (*Identity, error) {
	addresses := []string{}
	if strings.TrimSpace(r.Config.Interface.Addresses.V4) != "" {
		addresses = append(addresses, strings.TrimSpace(r.Config.Interface.Addresses.V4)+"/32")
	}
	if strings.TrimSpace(r.Config.Interface.Addresses.V6) != "" {
		addresses = append(addresses, strings.TrimSpace(r.Config.Interface.Addresses.V6)+"/128")
	}
	peerPublicKey := ""
	endpoint := ""
	if len(r.Config.Peers) > 0 {
		peerPublicKey = r.Config.Peers[0].PublicKey
		endpoint = r.Config.Peers[0].Endpoint.Host
	}
	return ImportManualIdentity(ManualIdentity{
		DeviceID:           r.ID,
		ClientID:           r.Config.ClientID,
		Token:              r.Token,
		AccountID:          r.Account.ID,
		AccountType:        r.Account.AccountType,
		License:            r.Account.License,
		PrivateKey:         privateKey,
		InterfaceAddresses: addresses,
		PeerPublicKey:      peerPublicKey,
		Endpoint:           endpoint,
		DNS:                []string{"1.1.1.1", "1.0.0.1"},
	})
}

func (r apiDeviceResponse) toStatus() *DeviceStatus {
	accountType := strings.TrimSpace(r.Account.AccountType)
	deviceID := strings.TrimSpace(r.ID)
	status := &DeviceStatus{
		DeviceID:    deviceID,
		DeviceName:  strings.TrimSpace(r.Name),
		DeviceType:  strings.TrimSpace(r.Type),
		AccountID:   strings.TrimSpace(r.Account.ID),
		AccountType: accountType,
		WARPPlus:    strings.EqualFold(accountType, "premium") || strings.TrimSpace(r.Account.License) != "",
		Active:      apiBoolWithDefault(r.Active, apiBoolWithDefault(r.Enabled, deviceID != "")),
	}
	for _, device := range r.Account.Devices {
		boundID := strings.TrimSpace(device.ID)
		status.BoundDevices = append(status.BoundDevices, BoundDevice{
			DeviceID:   boundID,
			Name:       strings.TrimSpace(device.Name),
			DeviceType: strings.TrimSpace(device.Type),
			Active:     apiBoolWithDefault(device.Active, apiBoolWithDefault(device.Enabled, boundID != "")),
			Current:    boundID != "" && boundID == deviceID,
		})
	}
	return status
}

func apiBoolWithDefault(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}
