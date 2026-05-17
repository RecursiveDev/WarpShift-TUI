package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/RecursiveDev/WarpShift-TUI/internal/app"
	"github.com/RecursiveDev/WarpShift-TUI/internal/cli"
)

var version = "dev"

func main() {
	application, err := app.New(app.Metadata{Name: "WarpShift-TUI", Version: version})
	if err != nil {
		fmt.Fprintf(os.Stderr, "warpshift: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	command := cli.New(application, os.Stdout, os.Stderr)
	os.Exit(command.Run(ctx, os.Args[1:]))
}
