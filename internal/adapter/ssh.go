package adapter

import (
	"context"
	"path/filepath"
	"strings"

	"idctl/internal/model"
	"idctl/internal/sys"
)

type SSH struct{}

func (SSH) Name() string { return "ssh" }

func (SSH) Read(ctx context.Context, id *model.Identity) {
	s := &id.SSH
	if !sys.Has("ssh-add") {
		return
	}
	s.Present = true
	out, err := sys.Out(ctx, "ssh-add", "-l")
	// ssh-add -l exits 1 with "The agent has no identities."
	if err != nil || strings.Contains(out, "no identities") || out == "" {
		s.AgentEmpty = true
		return
	}
	for _, line := range strings.Split(out, "\n") {
		// Format: "<bits> SHA256:<fp> <comment...> (<TYPE>)"
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		key := model.SSHKey{Fingerprint: f[1]}
		if t := f[len(f)-1]; strings.HasPrefix(t, "(") {
			key.Type = strings.Trim(t, "()")
			key.Comment = strings.Join(f[2:len(f)-1], " ")
		} else {
			key.Comment = strings.Join(f[2:], " ")
		}
		s.AgentKeys = append(s.AgentKeys, key)
	}
}

// Diff is best-effort: ssh-agent has no concept of a single "active" key, so we
// only flag when the profile's key clearly isn't loaded at all.
func (SSH) Diff(id *model.Identity, p *model.Profile) []model.Mismatch {
	if p.SSH.Key == "" || !id.SSH.Present {
		return nil
	}
	want := filepath.Base(expandPath(p.SSH.Key))
	if id.SSH.AgentEmpty {
		return []model.Mismatch{{
			Adapter: "ssh", Field: "key", Current: "(agent empty)", Expected: want,
			Risk: model.RiskLow, Explain: "ssh-agent has no keys loaded",
		}}
	}
	for _, k := range id.SSH.AgentKeys {
		if strings.Contains(k.Comment, want) || strings.Contains(k.Comment, p.SSH.Key) {
			return nil
		}
	}
	return []model.Mismatch{{
		Adapter: "ssh", Field: "key", Current: "(not loaded)", Expected: want,
		Risk: model.RiskLow, Explain: "the profile's ssh key does not appear to be loaded in the agent",
	}}
}
