package warp

import (
	"context"
	"errors"
	"strings"
)

// ErrOfficialLicenseBindingDeferred is returned because direct WARP+ license binding
// would require live account API behavior that is intentionally outside this project.
var ErrOfficialLicenseBindingDeferred = errors.New("official WARP+ license binding deferred: use Cloudflare's official WARP clients or warp-cli registration license command")

// OfficialLicenseBindingRequest describes an explicit user-owned official key binding request.
// The key is validated only for presence and is never stored or sent over the network here.
type OfficialLicenseBindingRequest struct {
	Identity         Identity
	LicenseKey       string
	ExplicitConsent  bool
	AcknowledgedGate bool
}

// BindOfficialLicense is a coded safety gate for WARP+ official key binding.
// It rejects non-consensual requests and intentionally performs no live API calls,
// account registration, key generation, cloning, or referral automation.
func BindOfficialLicense(ctx context.Context, request OfficialLicenseBindingRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !request.ExplicitConsent || !request.AcknowledgedGate {
		return errors.New("explicit consent and safety-gate acknowledgment are required for official license binding")
	}
	if strings.TrimSpace(request.LicenseKey) == "" {
		return errors.New("official license key is required")
	}
	if err := validateIdentity(request.Identity); err != nil {
		return err
	}
	return ErrOfficialLicenseBindingDeferred
}
