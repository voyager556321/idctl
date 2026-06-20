package risk

import (
	"testing"

	"github.com/voyager556321/idctl/internal/model"
)

func workProfile() *model.Profile {
	return &model.Profile{
		Name: "work",
		Git:  model.GitExpect{Email: "me@company.com", Name: "Me"},
		AWS:  model.AWSExpect{Profile: "work-sso"},
		Kube: model.KubeExpect{Context: "work-eks"},
		SSH:  model.SSHExpect{Key: "~/.ssh/id_work"},
	}
}

func gitOnlyProfile() *model.Profile {
	return &model.Profile{Name: "work", Git: model.GitExpect{Email: "me@company.com"}}
}

func kubeOnlyProfile() *model.Profile {
	return &model.Profile{Name: "work", Kube: model.KubeExpect{Context: "work-eks"}}
}

func TestAnalyzeSkipsNoiseOutsideRepo(t *testing.T) {
	p := workProfile()
	id := &model.Identity{
		Git:  model.GitState{Present: true, InRepo: false, EffectiveName: "Me", EffectiveEmail: "me@company.com"},
		AWS:  model.AWSState{Profile: "work-sso"},
		Kube: model.KubeState{Present: true, Context: "work-eks"},
		SSH:  model.SSHState{Present: true, AgentKeys: []model.SSHKey{{Comment: "id_work"}}},
	}
	fs := Analyze(id, p)
	if len(fs) != 0 {
		t.Fatalf("expected no findings outside repo with matching aws, got %d: %+v", len(fs), fs)
	}
}

func TestAnalyzeGitEmailMismatchInRepo(t *testing.T) {
	p := gitOnlyProfile()
	id := &model.Identity{
		Git: model.GitState{
			Present: true, InRepo: true,
			EffectiveEmail: "me@personal.dev",
		},
	}
	fs := Analyze(id, p)
	if len(fs) != 1 || fs[0].ID != "git.email" || fs[0].Risk != model.RiskHigh {
		t.Fatalf("expected one high git.email finding, got %+v", fs)
	}
	if fs[0].Fix == "" || fs[0].Impact == "" {
		t.Fatalf("finding must include fix and impact: %+v", fs[0])
	}
}

func TestAnalyzeSSHMismatch(t *testing.T) {
	p := &model.Profile{Name: "work", SSH: model.SSHExpect{Key: "~/.ssh/id_work"}}
	id := &model.Identity{
		SSH: model.SSHState{Present: true, AgentEmpty: true},
	}
	fs := Analyze(id, p)
	found := false
	for _, f := range fs {
		if f.ID == "ssh.key" {
			found = true
			if f.Title != "SSH identity mismatch" {
				t.Errorf("title: %q", f.Title)
			}
			if f.Fix != "ssh-add ~/.ssh/id_work" {
				t.Errorf("fix: %q", f.Fix)
			}
		}
	}
	if !found {
		t.Fatalf("expected ssh.key finding, got %+v", fs)
	}
}

func TestAnalyzeKubectlMissing(t *testing.T) {
	p := kubeOnlyProfile()
	id := &model.Identity{}
	fs := Analyze(id, p)
	if len(fs) != 1 || fs[0].ID != "kubectl.missing" {
		t.Fatalf("expected kubectl.missing, got %+v", fs)
	}
}

func TestAnalyzeSigningSanity(t *testing.T) {
	id := &model.Identity{
		Git: model.GitState{Present: true, GpgSign: true, SigningKey: ""},
	}
	fs := Analyze(id, nil)
	if len(fs) != 1 || fs[0].ID != "git.signingkey" {
		t.Fatalf("expected signing sanity finding, got %+v", fs)
	}
}

func TestBySeverityOrdering(t *testing.T) {
	fs := []Finding{
		{ID: "a", Risk: model.RiskLow},
		{ID: "b", Risk: model.RiskHigh},
		{ID: "c", Risk: model.RiskMedium},
	}
	groups := BySeverity(fs)
	if len(groups) != 3 || groups[0].Level != model.RiskHigh {
		t.Fatalf("bad grouping: %+v", groups)
	}
}
