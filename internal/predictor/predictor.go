// Package predictor turns the current identity STATE into per-ACTION risk.
//
// Where status/doctor answer "what is my identity?", the predictor answers
// "what identity will my next git/aws/kubectl/ssh action actually use, and is
// that the one I expect?". It is pure: it consumes the already-collected
// model.Identity (plus the configured profiles) and computes a verdict per
// action. It performs no I/O and depends on no external service.
package predictor

import (
	"fmt"
	"strings"

	"github.com/voyager556321/idctl/internal/engine"
	"github.com/voyager556321/idctl/internal/model"
)

// Action identifiers, also accepted by `idctl predict --action`.
const (
	ActGitCommit = "git-commit"
	ActGitPush   = "git-push"
	ActAWS       = "aws"
	ActKubectl   = "kubectl"
	ActSSH       = "ssh"
)

// ActionRisk is the verdict for a single upcoming action.
type ActionRisk struct {
	Action      string     // e.g. "git commit"
	Key         string     // stable id, e.g. ActGitCommit (for --action filtering)
	Subject     string     // the identity/value the action will use
	RiskLevel   model.Risk // reuses the same risk scale as doctor
	Explanation string
}

// Predict returns the risk for every action. `expected` may be nil (no profile
// selected); `all` is every configured profile, used to label which profile the
// current identity actually corresponds to ("will use PERSONAL identity").
func Predict(id *model.Identity, expected *model.Profile, all map[string]model.Profile) []ActionRisk {
	var mm []model.Mismatch
	if expected != nil {
		mm = engine.DiffAll(id, expected) // single source of truth for risk levels
	}
	return []ActionRisk{
		gitCommit(id, expected, all, mm),
		gitPush(id, expected),
		awsOp(id, expected, find(mm, "aws", "profile")),
		kubectlOp(id, expected, find(mm, "kubectl", "context")),
		sshConnect(id, expected),
	}
}

// PredictOne returns the single action matching key, or false.
func PredictOne(id *model.Identity, expected *model.Profile, all map[string]model.Profile, key string) (ActionRisk, bool) {
	for _, r := range Predict(id, expected, all) {
		if r.Key == key {
			return r, true
		}
	}
	return ActionRisk{}, false
}

// MaxRisk returns the highest risk across actions.
func MaxRisk(rs []ActionRisk) model.Risk {
	m := model.RiskNone
	for _, r := range rs {
		if r.RiskLevel > m {
			m = r.RiskLevel
		}
	}
	return m
}

func find(mm []model.Mismatch, adapter, field string) *model.Mismatch {
	for i := range mm {
		if mm[i].Adapter == adapter && mm[i].Field == field {
			return &mm[i]
		}
	}
	return nil
}

// profileForEmail reverse-maps a git email to a configured profile name.
func profileForEmail(all map[string]model.Profile, email string) string {
	for name, p := range all {
		if p.Git.Email != "" && p.Git.Email == email {
			return name
		}
	}
	return ""
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

// ---- per-action rules ------------------------------------------------------

func gitCommit(id *model.Identity, expected *model.Profile, all map[string]model.Profile, mm []model.Mismatch) ActionRisk {
	r := ActionRisk{Action: "git commit", Key: ActGitCommit}
	if !id.Git.Present {
		r.Explanation = "git is not installed"
		return r
	}
	if !id.Git.InRepo {
		r.Subject = id.Git.EffectiveEmail
		r.Explanation = "not inside a git repo — commit not applicable here"
		return r
	}
	email := id.Git.EffectiveEmail
	if name := profileForEmail(all, email); name != "" {
		r.Subject = fmt.Sprintf("%s identity (%s)", strings.ToUpper(name), email)
	} else {
		r.Subject = email + " (unrecognised profile)"
	}
	m := find(mm, "git", "email")
	switch {
	case expected == nil || expected.Git.Email == "":
		r.Explanation = "no expected git identity to compare against"
	case m == nil:
		r.Explanation = "commit will be authored with the expected identity"
	default:
		r.RiskLevel = m.Risk
		r.Explanation = fmt.Sprintf("commit will be authored as %s, not the expected %s",
			email, expected.Git.Email)
	}
	// Signing is part of the commit action.
	if s := find(mm, "git", "signingkey"); s != nil && s.Risk > r.RiskLevel {
		r.RiskLevel = s.Risk
		r.Explanation += "; " + s.Explain
	}
	return r
}

func gitPush(id *model.Identity, expected *model.Profile) ActionRisk {
	r := ActionRisk{Action: "git push", Key: ActGitPush}
	if !id.Git.Present || !id.Git.InRepo {
		r.Explanation = "not inside a git repo"
		return r
	}
	if id.Git.RemoteURL == "" {
		r.Subject = "(no origin remote)"
		r.Explanation = "current repo has no 'origin' remote to push to"
		return r
	}
	switch id.Git.RemoteProto {
	case "ssh":
		r.Subject = "ssh key for " + id.Git.RemoteHost
		if expected == nil || expected.SSH.Key == "" {
			r.RiskLevel = model.RiskLow
			r.Explanation = fmt.Sprintf("push to %s authenticates over SSH with whichever agent key it accepts", id.Git.RemoteHost)
			return r
		}
		if keyLoaded(id, expected.SSH.Key) {
			r.Explanation = fmt.Sprintf("push to %s over SSH; your profile key appears loaded", id.Git.RemoteHost)
		} else {
			r.RiskLevel = model.RiskMedium
			r.Explanation = fmt.Sprintf("push to %s over SSH; expected key %s is NOT loaded — a different key may authenticate you",
				id.Git.RemoteHost, expected.SSH.Key)
		}
	case "https":
		r.Subject = "git credential helper"
		r.RiskLevel = model.RiskLow
		r.Explanation = fmt.Sprintf("push to %s over HTTPS uses your credential helper, which idctl cannot inspect", id.Git.RemoteHost)
	default:
		r.Subject = id.Git.RemoteURL
		r.Explanation = "remote protocol not recognised; cannot predict the push identity"
	}
	return r
}

func awsOp(id *model.Identity, expected *model.Profile, m *model.Mismatch) ActionRisk {
	r := ActionRisk{Action: "aws cli", Key: ActAWS, Subject: id.AWS.Profile}
	if id.AWS.Verified {
		r.Subject = fmt.Sprintf("%s (account %s)", id.AWS.Profile, id.AWS.Account)
	}
	switch {
	case expected == nil || expected.AWS.Profile == "":
		r.Explanation = "no expected aws profile to compare against"
	case m == nil:
		r.Explanation = fmt.Sprintf("aws commands will use profile %q (expected)", id.AWS.Profile)
	default:
		r.RiskLevel = m.Risk
		r.Explanation = fmt.Sprintf("aws commands will hit profile %q, not the expected %q",
			id.AWS.Profile, expected.AWS.Profile)
	}
	return r
}

func kubectlOp(id *model.Identity, expected *model.Profile, m *model.Mismatch) ActionRisk {
	r := ActionRisk{Action: "kubectl apply", Key: ActKubectl}
	if !id.Kube.Present {
		r.Explanation = "kubectl is not installed"
		return r
	}
	r.Subject = "context " + id.Kube.Context
	switch {
	case expected == nil || expected.Kube.Context == "":
		r.Explanation = "no expected kube context to compare against"
	case m == nil:
		r.Explanation = fmt.Sprintf("kubectl will act on context %q (correct)", id.Kube.Context)
	default:
		r.RiskLevel = m.Risk
		r.Explanation = fmt.Sprintf("kubectl will act on context %q, not the expected %q",
			id.Kube.Context, expected.Kube.Context)
	}
	return r
}

func sshConnect(id *model.Identity, expected *model.Profile) ActionRisk {
	r := ActionRisk{Action: "ssh connect", Key: ActSSH}
	if !id.SSH.Present {
		r.Explanation = "ssh-agent not available"
		return r
	}
	r.Subject = fmt.Sprintf("%d key(s) in agent", len(id.SSH.AgentKeys))
	if id.SSH.AgentEmpty {
		r.Subject = "no keys in agent"
	}
	switch {
	case expected == nil || expected.SSH.Key == "":
		r.Explanation = "ssh offers every loaded agent key; servers pick the first accepted"
	case keyLoaded(id, expected.SSH.Key):
		r.Explanation = "your profile's ssh key is loaded and will be offered"
	default:
		r.RiskLevel = model.RiskLow
		r.Explanation = fmt.Sprintf("expected key %s is not loaded; another identity may be offered", expected.SSH.Key)
	}
	return r
}
