package warp

import (
	"context"
	"errors"
	"strings"
)

// ErrOfficialLicenseConsentRequired is returned when private-use license binding consent is missing.
var ErrOfficialLicenseConsentRequired = errors.New("explicit consent and private-use gate acknowledgment are required for official license binding")

// OfficialLicenseBindingRequest describes an explicit user-owned official key binding request.
// The key is validated only for presence and is never stored or sent over the network here.
type OfficialLicenseBindingRequest struct {
	Identity         Identity
	LicenseKey       string
	ExplicitConsent  bool
	AcknowledgedGate bool
}

// BindOfficialLicense validates the private-use consent gate and local inputs for a user-owned WARP+ key.
// API-backed binding is handled by BindOfficialLicenseToDevice.
func BindOfficialLicense(ctx context.Context, request OfficialLicenseBindingRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.ExplicitConsent || !request.AcknowledgedGate {
		return ErrOfficialLicenseConsentRequired
	}
	if strings.TrimSpace(request.LicenseKey) == "" {
		return errors.New("official license key is required")
	}
	if err := validateIdentity(request.Identity); err != nil {
		return err
	}
	return nil
}
