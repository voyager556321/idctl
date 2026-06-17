// Package engine wires the read-only adapters together: read all state, diff
// against an expected profile, and derive doctor findings + overall risk.
// It contains no mutation paths -- idctl is an inspector, not a fixer.
package engine

import (
	"context"

	"idctl/internal/adapter"
	"idctl/internal/model"
)

// ReadAll runs every adapter's Read into a fresh Identity.
func ReadAll(ctx context.Context) *model.Identity {
	id := &model.Identity{}
	for _, a := range adapter.All() {
		a.Read(ctx, id)
	}
	return id
}

// VerifyAWS performs the optional online STS read (account/arn).
func VerifyAWS(ctx context.Context, id *model.Identity) {
	adapter.AWS{}.Verify(ctx, id)
}

// DiffAll collects mismatches from every adapter against the expected profile.
func DiffAll(id *model.Identity, p *model.Profile) []model.Mismatch {
	var out []model.Mismatch
	for _, a := range adapter.All() {
		out = append(out, a.Diff(id, p)...)
	}
	return out
}

// SanityChecks are profile-independent findings.
func SanityChecks(id *model.Identity) []model.Mismatch {
	var out []model.Mismatch
	if id.Git.Present && id.Git.GpgSign && id.Git.SigningKey == "" {
		out = append(out, model.Mismatch{
			Adapter: "git", Field: "signingkey",
			Current: "(none)", Expected: "(a signing key)",
			Risk:    model.RiskMedium,
			Explain: "commit.gpgsign is on but no user.signingkey is set; commits will fail to sign",
		})
	}
	return out
}

// MaxRisk returns the highest risk across findings.
func MaxRisk(ms []model.Mismatch) model.Risk {
	r := model.RiskNone
	for _, m := range ms {
		if m.Risk > r {
			r = m.Risk
		}
	}
	return r
}
