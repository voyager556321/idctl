package adapter

import (
	"context"
	"strings"

	"github.com/voyager556321/idctl/internal/model"
	"github.com/voyager556321/idctl/internal/sys"
)

type Git struct{}

func (Git) Name() string { return "git" }

func (Git) Read(ctx context.Context, id *model.Identity) {
	if !sys.Has("git") {
		return
	}
	g := &id.Git
	g.Present = true
	g.GlobalName, _ = sys.Out(ctx, "git", "config", "--global", "user.name")
	g.GlobalEmail, _ = sys.Out(ctx, "git", "config", "--global", "user.email")

	if _, err := sys.Out(ctx, "git", "rev-parse", "--is-inside-work-tree"); err == nil {
		g.InRepo = true
		g.RepoName, _ = sys.Out(ctx, "git", "config", "--local", "user.name")
		g.RepoEmail, _ = sys.Out(ctx, "git", "config", "--local", "user.email")
		// Resolved value honours local > global precedence.
		g.EffectiveName, _ = sys.Out(ctx, "git", "config", "user.name")
		g.EffectiveEmail, _ = sys.Out(ctx, "git", "config", "user.email")
		if url, err := sys.Out(ctx, "git", "remote", "get-url", "origin"); err == nil {
			g.RemoteURL = url
			g.RemoteProto, g.RemoteHost = parseRemote(url)
		}
	} else {
		g.EffectiveName, g.EffectiveEmail = g.GlobalName, g.GlobalEmail
	}
	g.SigningKey, _ = sys.Out(ctx, "git", "config", "user.signingkey")
	if v, _ := sys.Out(ctx, "git", "config", "commit.gpgsign"); v == "true" {
		g.GpgSign = true
	}
}

func (Git) Diff(id *model.Identity, p *model.Profile) []model.Mismatch {
	var out []model.Mismatch
	g := id.Git
	if !g.Present || p.Git.Email == "" {
		return out
	}
	// In a repo, the effective email is what will sign commits -> highest stakes.
	risk := model.RiskMedium
	explain := "global git email differs from the expected profile"
	if g.InRepo {
		risk = model.RiskHigh
		explain = "commits in this repo would be authored with the wrong email"
	}
	if g.EffectiveEmail != p.Git.Email {
		out = append(out, model.Mismatch{
			Adapter: "git", Field: "email",
			Current: g.EffectiveEmail, Expected: p.Git.Email,
			Risk: risk, Explain: explain,
		})
	}
	if p.Git.Name != "" && g.EffectiveName != p.Git.Name {
		out = append(out, model.Mismatch{
			Adapter: "git", Field: "name",
			Current: g.EffectiveName, Expected: p.Git.Name,
			Risk: model.RiskLow, Explain: "git author name differs from the expected profile",
		})
	}
	if p.Git.SigningKey != "" && g.SigningKey != p.Git.SigningKey {
		out = append(out, model.Mismatch{
			Adapter: "git", Field: "signingkey",
			Current: g.SigningKey, Expected: p.Git.SigningKey,
			Risk: model.RiskMedium, Explain: "commits would be signed with the wrong GPG key",
		})
	}
	return out
}

// parseRemote classifies a git remote URL into (proto, host).
// Handles: scp-style "git@host:path", "ssh://git@host/path", "https://host/path".
func parseRemote(url string) (proto, host string) {
	switch {
	case strings.HasPrefix(url, "https://"):
		rest := strings.TrimPrefix(url, "https://")
		return "https", hostOf(rest)
	case strings.HasPrefix(url, "http://"):
		rest := strings.TrimPrefix(url, "http://")
		return "https", hostOf(rest)
	case strings.HasPrefix(url, "ssh://"):
		rest := strings.TrimPrefix(url, "ssh://")
		if i := strings.Index(rest, "@"); i >= 0 {
			rest = rest[i+1:]
		}
		return "ssh", hostOf(rest)
	case strings.Contains(url, "@") && strings.Contains(url, ":"):
		// scp-style: git@github.com:org/repo.git
		at := strings.Index(url, "@")
		colon := strings.Index(url, ":")
		if colon > at {
			return "ssh", url[at+1 : colon]
		}
	}
	return "", ""
}

func hostOf(s string) string {
	for _, sep := range []string{"/", ":"} {
		if i := strings.Index(s, sep); i >= 0 {
			s = s[:i]
		}
	}
	return s
}
