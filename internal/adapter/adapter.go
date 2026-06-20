// Package adapter contains one module per identity subsystem. Each adapter is a
// READ-ONLY observer: it fills its slice of the unified model and knows how to
// diff that slice against an expected profile. No adapter ever mutates system
// state -- idctl is strictly an inspector.
package adapter

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/voyager556321/idctl/internal/model"
)

// Adapter is implemented by every subsystem (git, aws, kube, ssh).
type Adapter interface {
	Name() string
	Read(ctx context.Context, id *model.Identity)
	Diff(id *model.Identity, p *model.Profile) []model.Mismatch
}

// All returns the adapters in display order.
func All() []Adapter {
	return []Adapter{Git{}, AWS{}, Kube{}, SSH{}}
}

// expandPath resolves a leading ~ to the user's home directory.
func expandPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p
}
