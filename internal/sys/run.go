// Package sys is a thin, safe wrapper around os/exec so adapters never hang
// the whole tool on a slow external command (looking at you, `aws sts`).
package sys

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds any single external command.
const DefaultTimeout = 4 * time.Second

// Out runs a command and returns its trimmed stdout. A non-zero exit or a
// missing binary returns an error; callers usually ignore it and treat the
// result as "unknown / not set", which is the correct behaviour for an
// inspector that must degrade gracefully.
func Out(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return strings.TrimSpace(string(out)), err
}

// Run executes a command for its side effect, surfacing stderr on failure.
func Run(ctx context.Context, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return errors.New(msg)
		}
		return err
	}
	return nil
}

// Has reports whether a binary exists on PATH.
func Has(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
