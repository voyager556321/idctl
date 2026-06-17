package config

import "testing"

func TestParseBasic(t *testing.T) {
	in := `# top comment
default_profile: work
profiles:
  work:
    git:
      name: "Vova Work"
      email: vova@company.com   # inline comment
      signingkey: ABCD1234
    aws:
      profile: work-sso
    kube:
      context: work-eks
      namespace: team-a
    ssh:
      key: ~/.ssh/id_work
  personal:
    git:
      name: Vova
      email: 'vova@personal.dev'
    aws:
      profile: default
`
	cfg, err := parse([]byte(in))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.Default != "work" {
		t.Errorf("default_profile = %q", cfg.Default)
	}
	if len(cfg.Order) != 2 || cfg.Order[0] != "work" || cfg.Order[1] != "personal" {
		t.Fatalf("order wrong: %v", cfg.Order)
	}
	w := cfg.Profiles["work"]
	if w.Git.Name != "Vova Work" {
		t.Errorf("git name = %q", w.Git.Name)
	}
	if w.Git.Email != "vova@company.com" {
		t.Errorf("inline comment not stripped: %q", w.Git.Email)
	}
	if w.Git.SigningKey != "ABCD1234" {
		t.Errorf("signingkey = %q", w.Git.SigningKey)
	}
	if w.AWS.Profile != "work-sso" {
		t.Errorf("aws = %q", w.AWS.Profile)
	}
	if w.Kube.Context != "work-eks" || w.Kube.Namespace != "team-a" {
		t.Errorf("kube = %+v", w.Kube)
	}
	if w.SSH.Key != "~/.ssh/id_work" {
		t.Errorf("ssh = %q", w.SSH.Key)
	}
	p := cfg.Profiles["personal"]
	if p.Git.Email != "vova@personal.dev" {
		t.Errorf("single-quote unquote failed: %q", p.Git.Email)
	}

	// Resolve precedence: explicit flag beats default.
	if got := cfg.Resolve("personal"); got == nil || got.Name != "personal" {
		t.Errorf("Resolve(explicit) failed: %+v", got)
	}
	if got := cfg.Resolve(""); got == nil || got.Name != "work" {
		t.Errorf("Resolve(default) failed: %+v", got)
	}
}

func TestParseRejectsUnknownDefault(t *testing.T) {
	in := "default_profile: ghost\nprofiles:\n  real:\n    aws:\n      profile: default\n"
	if _, err := parse([]byte(in)); err == nil {
		t.Fatal("expected error for unknown default_profile")
	}
}

func TestParseNoProfiles(t *testing.T) {
	if _, err := parse([]byte("foo: bar\n")); err == nil {
		t.Fatal("expected error for missing profiles")
	}
}

func TestStripCommentKeepsHashInQuotes(t *testing.T) {
	got := stripComment(`key: "a # b"`)
	if got != `key: "a # b"` {
		t.Errorf("stripped inside quotes: %q", got)
	}
}
