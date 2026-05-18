package warp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRegisterAccountUsesFakeServerAndStoresIdentitySecurely(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "state", "identity.json")
	var requestBody map[string]any

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/reg" {
			t.Fatalf("request = %s %s, want POST /reg", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&requestBody); err != nil {
			t.Fatalf("decode registration body: %v", err)
		}
		if strings.TrimSpace(requestBody["key"].(string)) == "" {
			t.Fatal("registration request missing generated public key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"device-secret-id",
			"token":"token-secret-value",
			"account":{"id":"account-secret-id","account_type":"limited"},
			"config":{
				"client_id":"` + base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) + `",
				"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:abcd::2"}},
				"peers":[{"public_key":"peer-public-key","endpoint":{"host":"engage.cloudflareclient.com:2408"}}]
			}
		}`))
	}))
	defer server.Close()

	client, err := NewAPIClient(APIClientConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewAPIClient returned unexpected error: %v", err)
	}
	identity, err := RegisterAccount(context.Background(), AccountRegistrationRequest{
		Client:           client,
		StorePath:        storePath,
		ExplicitConsent:  true,
		AcknowledgedGate: true,
	})
	if err != nil {
		t.Fatalf("RegisterAccount returned unexpected error: %v", err)
	}
	if deviceIDOK, tokenOK, accountTypeOK := identity.DeviceID == "device-secret-id", identity.Token == "token-secret-value", identity.AccountType == "limited"; !deviceIDOK || !tokenOK || !accountTypeOK {
		t.Fatalf("identity metadata mismatch: deviceIDOK=%t tokenOK=%t accountTypeOK=%t", deviceIDOK, tokenOK, accountTypeOK)
	}
	if identity.PrivateKey == "" || identity.PrivateKey == requestBody["key"] {
		t.Fatal("identity should store a generated private key distinct from the submitted public key")
	}
	loaded, err := LoadIdentity(storePath)
	if err != nil {
		t.Fatalf("LoadIdentity returned unexpected error: %v", err)
	}
	if tokenOK, clientIDPresent, reservedLen := loaded.Token == "token-secret-value", loaded.ClientID != "", len(loaded.Reserved); !tokenOK || !clientIDPresent || reservedLen != 3 {
		t.Fatalf("stored identity metadata mismatch: tokenOK=%t clientIDPresent=%t reservedLen=%d", tokenOK, clientIDPresent, reservedLen)
	}
	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat stored identity: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("stored identity mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestRegisterAccountRequiresConsentBeforeNetwork(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()
	client, err := NewAPIClient(APIClientConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewAPIClient returned unexpected error: %v", err)
	}

	_, err = RegisterAccount(context.Background(), AccountRegistrationRequest{Client: client, StorePath: filepath.Join(t.TempDir(), "identity.json")})
	if !errors.Is(err, ErrAccountAutomationConsentRequired) {
		t.Fatalf("RegisterAccount error = %v, want ErrAccountAutomationConsentRequired", err)
	}
	if called {
		t.Fatal("registration contacted API before explicit consent")
	}
}

func TestLicenseBindingAndStatusUseAPIClientWithoutLeakingSecrets(t *testing.T) {
	licenseKey := "license-secret-value"
	identity := Identity{
		DeviceID:           "device-secret-id",
		Token:              "token-secret-value",
		PrivateKey:         testPrivateKey(),
		InterfaceAddresses: []string{"172.16.0.2/32"},
		PeerPublicKey:      "peer-public-key",
		Endpoint:           "engage.cloudflareclient.com:2408",
		DNS:                []string{"1.1.1.1"},
	}
	seenPatch := false
	seenGet := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token-secret-value" {
			t.Fatal("Authorization header did not contain expected bearer token")
		}
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/reg/device-secret-id/account":
			seenPatch = true
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode license body: %v", err)
			}
			if body["license"] != licenseKey {
				t.Fatal("license request body did not contain submitted key")
			}
		case r.Method == http.MethodGet && r.URL.Path == "/reg/device-secret-id":
			seenGet = true
		default:
			t.Fatalf("unexpected request method=%s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"device-secret-id","name":"test-phone","type":"Android","active":true,"account":{"id":"account-secret-id","account_type":"premium","license":"redacted-server-license","devices":[{"id":"device-secret-id","name":"test-phone","type":"Android","active":true},{"id":"device-secondary-id","name":"laptop","type":"Windows","active":false}]}}`))
	}))
	defer server.Close()
	client, err := NewAPIClient(APIClientConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewAPIClient returned unexpected error: %v", err)
	}

	status, err := BindOfficialLicenseToDevice(context.Background(), OfficialLicenseAPIRequest{
		Client:           client,
		Identity:         identity,
		LicenseKey:       licenseKey,
		ExplicitConsent:  true,
		AcknowledgedGate: true,
	})
	if err != nil {
		errorMessage := err.Error()
		if strings.Contains(errorMessage, licenseKey) || strings.Contains(errorMessage, identity.Token) || strings.Contains(errorMessage, identity.DeviceID) {
			t.Fatal("license binding error leaked sensitive material")
		}
		t.Fatalf("BindOfficialLicenseToDevice returned unexpected error: %v", err)
	}
	if !seenPatch || status.AccountType != "premium" || !status.WARPPlus {
		t.Fatalf("license binding status mismatch: seenPatch=%t accountTypePremium=%t warpPlus=%t", seenPatch, status.AccountType == "premium", status.WARPPlus)
	}
	status, err = client.DeviceStatus(context.Background(), identity)
	if err != nil {
		t.Fatalf("DeviceStatus returned unexpected error: %v", err)
	}
	if !seenGet || status.DeviceID != "device-secret-id" || status.AccountID != "account-secret-id" {
		t.Fatalf("device status mismatch: seenGet=%t deviceIDOK=%t accountIDOK=%t", seenGet, status.DeviceID == "device-secret-id", status.AccountID == "account-secret-id")
	}
	if status.DeviceName != "test-phone" || status.DeviceType != "Android" || !status.Active {
		t.Fatalf("enriched device status mismatch: %+v", status)
	}
	if len(status.BoundDevices) != 2 || !status.BoundDevices[0].Current || status.BoundDevices[1].Active {
		t.Fatalf("bound devices mismatch: %+v", status.BoundDevices)
	}
}

func TestAPIClientErrorsRedactSensitiveResponseBodyAndURL(t *testing.T) {
	identity := Identity{
		DeviceID:           "device-secret-id",
		Token:              "token-secret-value",
		PrivateKey:         testPrivateKey(),
		InterfaceAddresses: []string{"172.16.0.2/32"},
		PeerPublicKey:      "peer-public-key",
		Endpoint:           "engage.cloudflareclient.com:2408",
		DNS:                []string{"1.1.1.1"},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "device-secret-id token-secret-value license-secret-value account-secret-id", http.StatusInternalServerError)
	}))
	defer server.Close()
	client, err := NewAPIClient(APIClientConfig{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("NewAPIClient returned unexpected error: %v", err)
	}

	_, err = client.DeviceStatus(context.Background(), identity)
	if err == nil {
		t.Fatal("expected API status error")
	}
	message := err.Error()
	for i, secret := range []string{"device-secret-id", "token-secret-value", "license-secret-value", "account-secret-id", server.URL} {
		if strings.Contains(message, secret) {
			t.Fatalf("API error leaked sensitive material at check index %d", i)
		}
	}
	if !strings.Contains(message, "status 500") {
		t.Fatalf("API error = %q, want sanitized status code", message)
	}
}

func TestUnsupportedAccountDeviceOperationsAreConsentGatedAndDoNotUseClient(t *testing.T) {
	if err := RenameDevice(context.Background(), DeviceOperationRequest{Name: "phone"}); !errors.Is(err, ErrAccountAutomationConsentRequired) {
		t.Fatalf("RenameDevice without consent error = %v, want consent error", err)
	}
	if err := RenameDevice(context.Background(), DeviceOperationRequest{Name: "phone", ExplicitConsent: true, AcknowledgedGate: true}); !errors.Is(err, ErrUnsupportedAccountOperation) {
		t.Fatalf("RenameDevice error = %v, want unsupported operation", err)
	}
	if err := DeactivateDevice(context.Background(), DeviceOperationRequest{ExplicitConsent: true, AcknowledgedGate: true}); !errors.Is(err, ErrUnsupportedAccountOperation) {
		t.Fatalf("DeactivateDevice error = %v, want unsupported operation", err)
	}
}
