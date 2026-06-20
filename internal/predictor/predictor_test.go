package predictor

import (
	"testing"

	"github.com/voyager556321/idctl/internal/model"
)

func profiles() map[string]model.Profile {
	return map[string]model.Profile{
		"personal": {Name: "personal", Git: model.GitExpect{Email: "me@personal.dev"}},
		"work": {Name: "work",
			Git:  model.GitExpect{Email: "me@company.com"},
			AWS:  model.AWSExpect{Profile: "work-sso"},
			Kube: model.KubeExpect{Context: "work-eks"},
			SSH:  model.SSHExpect{Key: "~/.ssh/id_work"}},
	}
}

func by(rs []ActionRisk, key string) ActionRisk {
	for _, r := range rs {
		if r.Key == key {
			return r
		}
	}
	return ActionRisk{}
}

func TestGitCommitMismatchIsHigh(t *testing.T) {
	all := profiles()
	exp := all["work"]
	id := &model.Identity{Git: model.GitState{
		Present: true, InRepo: true,
		EffectiveEmail: "me@personal.dev", // wrong identity for work
	}}
	rs := Predict(id, &exp, all)
	c := by(rs, ActGitCommit)
	if c.RiskLevel != model.RiskHigh {
		t.Errorf("expected high, got %s", c.RiskLevel)
	}
	if MaxRisk(rs) != model.RiskHigh {
		t.Errorf("MaxRisk should be high")
	}
}

func TestGitCommitMatchIsClean(t *testing.T) {
	all := profiles()
	exp := all["work"]
	id := &model.Identity{Git: model.GitState{
		Present: true, InRepo: true, EffectiveEmail: "me@company.com",
	}}
	c := by(Predict(id, &exp, all), ActGitCommit)
	if c.RiskLevel != model.RiskNone {
		t.Errorf("expected none, got %s", c.RiskLevel)
	}
}

func TestGitPushSSHKeyNotLoaded(t *testing.T) {
	all := profiles()
	exp := all["work"]
	id := &model.Identity{Git: model.GitState{
		Present: true, InRepo: true,
		RemoteURL: "git@github.com:org/repo.git", RemoteProto: "ssh", RemoteHost: "github.com",
	}}
	p := by(Predict(id, &exp, all), ActGitPush)
	if p.RiskLevel != model.RiskMedium {
		t.Errorf("expected medium (key not loaded), got %s", p.RiskLevel)
	}
}

func TestNoExpectedProfileIsQuiet(t *testing.T) {
	all := profiles()
	id := &model.Identity{Git: model.GitState{Present: true, InRepo: true, EffectiveEmail: "x@y.z"}}
	if MaxRisk(Predict(id, nil, all)) != model.RiskNone {
		t.Errorf("with no expected profile, nothing should be risky")
	}
}

func TestPredictOne(t *testing.T) {
	all := profiles()
	exp := all["work"]
	id := &model.Identity{Kube: model.KubeState{Present: true, Context: "prod-cluster"}}
	r, ok := PredictOne(id, &exp, all, ActKubectl)
	if !ok || r.RiskLevel != model.RiskHigh {
		t.Errorf("prod context mismatch should be high, got ok=%v risk=%s", ok, r.RiskLevel)
	}
}
