// Package risk is the single source of truth for actionable identity findings.
// It consumes observed state + an expected profile and returns only issues that
// warrant operator attention — no "healthy" lines, no N/A noise.
package risk

import (
	"fmt"
	"sort"
	"strings"

	"github.com/voyager556321/idctl/internal/engine"
	"github.com/voyager556321/idctl/internal/model"
)

// Finding is one actionable issue with enough context to act on it.
type Finding struct {
	ID       string
	Risk     model.Risk
	Title    string
	Problem  string // what is wrong
	Impact   string // why it matters
	Fix      string // suggested manual action (idctl never runs this)
	Current  string
	Expected string
	Source   string // git | aws | kubectl | ssh
}

// Analyze returns actionable findings only. Pass a verified Identity when AWS
// account confirmation matters (same as doctor / status --verify).
func Analyze(id *model.Identity, expected *model.Profile) []Finding {
	var out []Finding
	seen := map[string]bool{}

	add := func(f Finding) {
		if f.Risk <= model.RiskNone || seen[f.ID] {
			return
		}
		seen[f.ID] = true
		out = append(out, f)
	}

	if expected != nil {
		for _, m := range engine.DiffAll(id, expected) {
			if actionableMismatch(id, expected, m) {
				add(fromMismatch(m, expected, id))
			}
		}
		addExtra(id, expected, add)
	}

	for _, m := range engine.SanityChecks(id) {
		add(fromMismatch(m, expected, id))
	}

	escalate(&out, id)
	sortFindings(out)
	return out
}

// MaxRisk returns the highest severity across findings.
func MaxRisk(findings []Finding) model.Risk {
	r := model.RiskNone
	for _, f := range findings {
		if f.Risk > r {
			r = f.Risk
		}
	}
	return r
}

// BySeverity groups findings high → medium → low (empty groups omitted).
func BySeverity(findings []Finding) []struct {
	Level    model.Risk
	Findings []Finding
} {
	order := []model.Risk{model.RiskHigh, model.RiskMedium, model.RiskLow}
	var groups []struct {
		Level    model.Risk
		Findings []Finding
	}
	for _, level := range order {
		var g []Finding
		for _, f := range findings {
			if f.Risk == level {
				g = append(g, f)
			}
		}
		if len(g) > 0 {
			groups = append(groups, struct {
				Level    model.Risk
				Findings []Finding
			}{level, g})
		}
	}
	return groups
}

// actionableMismatch drops profile comparisons for tools that are not installed
// when the mismatch would not help the operator (handled separately).
func actionableMismatch(id *model.Identity, expected *model.Profile, m model.Mismatch) bool {
	switch m.Adapter {
	case "git":
		if !id.Git.Present {
			return false
		}
	case "kubectl":
		if !id.Kube.Present {
			return false
		}
	case "ssh":
		if !id.SSH.Present || expected.SSH.Key == "" {
			return false
		}
	case "aws":
		if expected.AWS.Profile == "" {
			return false
		}
	}
	return m.Risk > model.RiskNone
}

func addExtra(id *model.Identity, expected *model.Profile, add func(Finding)) {
	if expected.Kube.Context != "" && !id.Kube.Present {
		add(Finding{
			ID: "kubectl.missing", Risk: model.RiskMedium, Source: "kubectl",
			Title:    "kubectl not available",
			Problem:  "kubectl is not installed or not on PATH",
			Impact:   fmt.Sprintf("Cannot reach the expected context %q.", expected.Kube.Context),
			Expected: expected.Kube.Context,
			Fix:      fmt.Sprintf("Install kubectl, then: kubectl config use-context %s", expected.Kube.Context),
		})
	}
	if !id.Git.Present && (expected.Git.Email != "" || expected.Git.Name != "") {
		add(Finding{
			ID: "git.missing", Risk: model.RiskMedium, Source: "git",
			Title:   "git not available",
			Problem: "git is not installed or not on PATH",
			Impact:  "Cannot verify or use the expected git identity on this machine.",
			Fix:     "Install git and configure user.name / user.email for profile " + expected.Name,
		})
	}

}

func escalate(findings *[]Finding, id *model.Identity) {
	for i := range *findings {
		f := &(*findings)[i]
		if f.ID == "ssh.key" && id.Git.InRepo && id.Git.RemoteProto == "ssh" {
			if f.Risk < model.RiskMedium {
				f.Risk = model.RiskMedium
			}
			if !strings.Contains(f.Impact, "git push") {
				f.Impact += fmt.Sprintf(" Git push to %s uses the same SSH identity.", id.Git.RemoteHost)
			}
		}
	}
}

func fromMismatch(m model.Mismatch, p *model.Profile, id *model.Identity) Finding {
	f := Finding{
		ID: m.Adapter + "." + m.Field,
		Risk: m.Risk, Current: m.Current, Expected: m.Expected, Source: m.Adapter,
	}
	switch {
	case m.Adapter == "git" && m.Field == "email":
		f.Title = "Git email mismatch"
		f.Problem = fmt.Sprintf("Effective email is %s; profile expects %s", disp(m.Current), disp(m.Expected))
		if id.Git.InRepo {
			f.Impact = "Commits in this repository will be authored with the wrong identity."
		} else {
			f.Impact = "Commits may use the wrong identity when working inside a repository."
		}
		scope := "--global"
		if id.Git.InRepo {
			scope = "--local"
		}
		f.Fix = fmt.Sprintf("git config %s user.email %s", scope, m.Expected)

	case m.Adapter == "git" && m.Field == "name":
		f.Title = "Git author name mismatch"
		f.Problem = fmt.Sprintf("Effective name is %s; profile expects %s", disp(m.Current), disp(m.Expected))
		f.Impact = "Commits will show the wrong author name."
		scope := "--global"
		if id.Git.InRepo {
			scope = "--local"
		}
		f.Fix = fmt.Sprintf("git config %s user.name %q", scope, m.Expected)

	case m.Adapter == "git" && m.Field == "signingkey":
		if m.Expected == "(a signing key)" {
			f.Title = "Git signing not configured"
			f.Problem = "commit.gpgsign is enabled but user.signingkey is not set"
			f.Impact = "Commits will fail to sign."
			f.Fix = "git config user.signingkey <your-key>   # or: git config --unset commit.gpgsign"
		} else {
			f.Title = "Git signing key mismatch"
			f.Problem = fmt.Sprintf("Signing key is %s; profile expects %s", disp(m.Current), disp(m.Expected))
			f.Impact = "Commits may be signed with the wrong GPG key or fail to sign."
			if p != nil && p.Git.SigningKey != "" {
				f.Fix = fmt.Sprintf("git config user.signingkey %s", p.Git.SigningKey)
			} else {
				f.Fix = "git config user.signingkey <your-key>   # or: git config --unset commit.gpgsign"
			}
		}

	case m.Adapter == "aws" && m.Field == "profile":
		f.Title = "AWS profile mismatch"
		f.Problem = fmt.Sprintf("Active profile is %s; profile expects %s", disp(m.Current), disp(m.Expected))
		if id.AWS.Verified {
			f.Impact = fmt.Sprintf("AWS commands hit account %s under the wrong profile.", id.AWS.Account)
		} else {
			f.Impact = "AWS CLI commands may target the wrong account or role."
		}
		if p != nil {
			f.Fix = fmt.Sprintf("export AWS_PROFILE=%s", p.AWS.Profile)
		}

	case m.Adapter == "kubectl" && m.Field == "context":
		f.Title = "Kubernetes context mismatch"
		f.Problem = fmt.Sprintf("Current context is %s; profile expects %s", disp(m.Current), disp(m.Expected))
		f.Impact = "kubectl commands will act on the wrong cluster."
		if p != nil {
			f.Fix = fmt.Sprintf("kubectl config use-context %s", p.Kube.Context)
		}

	case m.Adapter == "kubectl" && m.Field == "namespace":
		f.Title = "Kubernetes namespace mismatch"
		f.Problem = fmt.Sprintf("Default namespace is %s; profile expects %s", disp(m.Current), disp(m.Expected))
		f.Impact = "kubectl commands may target the wrong namespace."
		if p != nil {
			f.Fix = fmt.Sprintf("kubectl config set-context --current --namespace=%s", p.Kube.Namespace)
		}

	case m.Adapter == "ssh" && m.Field == "key":
		f.Title = "SSH identity mismatch"
		want := m.Expected
		if p != nil && p.SSH.Key != "" {
			want = p.SSH.Key
		}
		f.Problem = fmt.Sprintf("Expected key %s is not loaded in ssh-agent", want)
		f.Impact = "SSH connections may authenticate as another identity."
		if p != nil {
			f.Fix = fmt.Sprintf("ssh-add %s", p.SSH.Key)
		}
		f.Expected = want

	default:
		f.Title = m.Adapter + " " + m.Field
		f.Problem = m.Explain
		f.Impact = m.Explain
	}

	return f
}

func keyLoaded(id *model.Identity, keyPath string) bool {
	base := keyPath
	if i := strings.LastIndexByte(keyPath, '/'); i >= 0 {
		base = keyPath[i+1:]
	}
	for _, k := range id.SSH.AgentKeys {
		if strings.Contains(k.Comment, base) || strings.Contains(k.Comment, keyPath) {
			return true
		}
	}
	return false
}

func disp(s string) string {
	if s == "" {
		return "(unset)"
	}
	return s
}

func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Risk != fs[j].Risk {
			return fs[i].Risk > fs[j].Risk
		}
		if fs[i].Source != fs[j].Source {
			return fs[i].Source < fs[j].Source
		}
		return fs[i].ID < fs[j].ID
	})
}
