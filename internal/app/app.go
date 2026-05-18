package app

import (
	"errors"
	"strings"
)

// Metadata describes the application build exposed by the CLI and TUI layers.
type Metadata struct {
	Name    string
	Version string
}

// App owns process-wide application metadata and capability boundaries.
type App struct {
	metadata Metadata
}

// New validates metadata and creates an application instance.
func New(metadata Metadata) (*App, error) {
	metadata.Name = strings.TrimSpace(metadata.Name)
	metadata.Version = strings.TrimSpace(metadata.Version)

	if metadata.Name == "" {
		return nil, errors.New("app name is required")
	}
	if metadata.Version == "" {
		metadata.Version = "dev"
	}

	return &App{metadata: metadata}, nil
}

// Name returns the application display name.
func (a *App) Name() string {
	return a.metadata.Name
}

// Version returns the application version.
func (a *App) Version() string {
	return a.metadata.Version
}

// SafeCapabilities returns the capability areas exposed by the application.
func (a *App) SafeCapabilities() []string {
	return []string{
		"CLI command surface",
		"TUI shell",
		"WARP status boundary",
		"local proxy boundary",
	}
}
