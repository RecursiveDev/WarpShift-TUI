package warp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOfficialLicenseBindingAcceptsConsentedPrivateUseRequestWithoutSecretEcho(t *testing.T) {
	identity, err := ImportManualIdentity(validManualIdentity())
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}
	licenseKey := "official-user-owned-key"

	err = BindOfficialLicense(context.Background(), OfficialLicenseBindingRequest{
		Identity:         *identity,
		LicenseKey:       licenseKey,
		ExplicitConsent:  true,
		AcknowledgedGate: true,
	})
	if err != nil {
		if strings.Contains(err.Error(), licenseKey) || strings.Contains(err.Error(), identity.PrivateKey) {
			t.Fatalf("license binding error leaked sensitive material: %v", err)
		}
		t.Fatalf("BindOfficialLicense returned unexpected error: %v", err)
	}
}

func TestOfficialLicenseBindingRequiresExplicitConsentBeforeValidation(t *testing.T) {
	identity, err := ImportManualIdentity(validManualIdentity())
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}

	err = BindOfficialLicense(context.Background(), OfficialLicenseBindingRequest{
		Identity:   *identity,
		LicenseKey: "official-user-owned-key",
	})
	if !errors.Is(err, ErrOfficialLicenseConsentRequired) {
		t.Fatalf("BindOfficialLicense error = %v, want ErrOfficialLicenseConsentRequired", err)
	}
	if strings.Contains(err.Error(), "official-user-owned-key") || strings.Contains(err.Error(), identity.PrivateKey) {
		t.Fatalf("license binding consent error leaked sensitive material: %v", err)
	}
	if !strings.Contains(err.Error(), "explicit consent") {
		t.Fatalf("BindOfficialLicense error = %v, want explicit consent guidance", err)
	}
}
