package warp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unicode"
)

// ErrInvalidProfileName is returned when a profile name could escape the profile store.
var ErrInvalidProfileName = errors.New("invalid profile name")

// ProfileStore stores named local WARP identities in one directory.
type ProfileStore struct {
	root string
}

// ProfileSummary is non-secret metadata for profile listing.
type ProfileSummary struct {
	Name                  string
	Active                bool
	Endpoint              string
	InterfaceAddressCount int
	DNSCount              int
}

type profileState struct {
	Active string `json:"active"`
}

// NewProfileStore creates a profile store rooted at a local directory.
func NewProfileStore(root string) (*ProfileStore, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, errors.New("profile store directory is required")
	}
	cleaned, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("profile store directory invalid: %w", err)
	}
	if err := os.MkdirAll(cleaned, 0o700); err != nil {
		return nil, fmt.Errorf("create profile store: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(cleaned, 0o700); err != nil {
			return nil, fmt.Errorf("set profile store permissions: %w", err)
		}
	}
	return &ProfileStore{root: cleaned}, nil
}

// ProfileIdentityPath returns the secure identity path for a validated profile name.
func (s *ProfileStore) ProfileIdentityPath(name string) (string, error) {
	name, err := validateProfileName(name)
	if err != nil {
		return "", err
	}
	path := filepath.Join(s.root, name+".json")
	cleaned := filepath.Clean(path)
	if !isPathInside(s.root, cleaned) {
		return "", ErrInvalidProfileName
	}
	return cleaned, nil
}

// ImportManualIdentityFile imports a manual identity JSON file into a named profile.
func (s *ProfileStore) ImportManualIdentityFile(name, sourcePath string) (*Identity, error) {
	path, err := s.ProfileIdentityPath(name)
	if err != nil {
		return nil, err
	}
	return ImportManualIdentityFile(sourcePath, path)
}

// LoadProfile loads and validates one named profile.
func (s *ProfileStore) LoadProfile(name string) (*Identity, error) {
	path, err := s.ProfileIdentityPath(name)
	if err != nil {
		return nil, err
	}
	return LoadIdentity(path)
}

// ListProfiles returns non-secret summaries for all stored profiles.
func (s *ProfileStore) ListProfiles() ([]ProfileSummary, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("list profiles: %w", err)
	}
	active, err := s.ActiveProfile()
	if err != nil {
		return nil, err
	}
	summaries := []ProfileSummary{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == filepath.Base(s.activePath()) || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".json")
		if _, err := validateProfileName(name); err != nil {
			continue
		}
		identity, err := s.LoadProfile(name)
		if err != nil {
			return nil, fmt.Errorf("load profile %q: %w", name, err)
		}
		summaries = append(summaries, ProfileSummary{
			Name:                  name,
			Active:                name == active,
			Endpoint:              identity.Endpoint,
			InterfaceAddressCount: len(identity.InterfaceAddresses),
			DNSCount:              len(identity.DNS),
		})
	}
	sort.Slice(summaries, func(i, j int) bool { return summaries[i].Name < summaries[j].Name })
	return summaries, nil
}

// SwitchProfile marks an existing profile as active.
func (s *ProfileStore) SwitchProfile(name string) error {
	name, err := validateProfileName(name)
	if err != nil {
		return err
	}
	if _, err := s.LoadProfile(name); err != nil {
		return err
	}
	return writeJSONSecure(s.activePath(), profileState{Active: name})
}

// ActiveProfile returns the active profile name, or an empty string when none is selected.
func (s *ProfileStore) ActiveProfile() (string, error) {
	path := s.activePath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", nil
	} else if err != nil {
		return "", fmt.Errorf("stat active profile: %w", err)
	}
	if err := ensureSecureFileMode(path); err != nil {
		return "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read active profile: %w", err)
	}
	var state profileState
	if err := json.Unmarshal(data, &state); err != nil {
		return "", fmt.Errorf("parse active profile: %w", err)
	}
	name, err := validateProfileName(state.Active)
	if err != nil {
		return "", err
	}
	return name, nil
}

// DeleteProfile removes one named profile and clears the active marker if it selected that profile.
func (s *ProfileStore) DeleteProfile(name string) error {
	name, err := validateProfileName(name)
	if err != nil {
		return err
	}
	path, err := s.ProfileIdentityPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("delete profile: %w", err)
	}
	active, err := s.ActiveProfile()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if active == name {
		if err := os.Remove(s.activePath()); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("clear active profile: %w", err)
		}
	}
	return nil
}

func (s *ProfileStore) activePath() string {
	return filepath.Join(s.root, ".active-profile.json")
}

func validateProfileName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || strings.HasPrefix(name, ".") || len(name) > 64 {
		return "", ErrInvalidProfileName
	}
	if strings.ContainsAny(name, `/\\`) || filepath.Base(name) != name {
		return "", ErrInvalidProfileName
	}
	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' {
			continue
		}
		return "", ErrInvalidProfileName
	}
	return name, nil
}

func isPathInside(root, candidate string) bool {
	root = filepath.Clean(root)
	candidate = filepath.Clean(candidate)
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel))
}
