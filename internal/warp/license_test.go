package warp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOfficialLicenseBindingIsSafetyGatedWithoutNetworkOrSecretEcho(t *testing.T) {
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
	if !errors.Is(err, ErrOfficialLicenseBindingDeferred) {
		t.Fatalf("BindOfficialLicense error = %v, want ErrOfficialLicenseBindingDeferred", err)
	}
	if strings.Contains(err.Error(), licenseKey) || strings.Contains(err.Error(), identity.PrivateKey) {
		t.Fatalf("license binding error leaked sensitive material: %v", err)
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
	if err == nil || !strings.Contains(err.Error(), "explicit consent") {
		t.Fatalf("BindOfficialLicense error = %v, want explicit consent guidance", err)
	}
}
