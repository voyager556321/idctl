// Package config loads ~/.idctl/config.yaml. The tool is read-only and never
// writes identity state; the only file it may create is its OWN example config
// via `init`. The "expected" profile to compare against is chosen at runtime
// (a --profile flag) or falls back to the optional `default_profile:` key.
//
// It ships a tiny YAML-subset parser instead of a dependency so idctl stays a
// single dependency-free static binary. See parseYAML for what is supported.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"idctl/internal/model"
)

// Config is the parsed config file.
type Config struct {
	Profiles map[string]model.Profile
	Order    []string // declaration order, for stable listing
	Default  string   // default_profile, may be ""
}

// Dir returns ~/.idctl, honouring $IDCTL_HOME for tests.
func Dir() string {
	if h := os.Getenv("IDCTL_HOME"); h != "" {
		return h
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".idctl")
}

func ConfigPath() string { return filepath.Join(Dir(), "config.yaml") }

// Load reads and parses the config file.
func Load() (*Config, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no config at %s (run `idctl init`)", ConfigPath())
		}
		return nil, err
	}
	return parse(data)
}

// Resolve picks the expected profile: an explicit name (from --profile) wins,
// else the config's default_profile. Returns nil if neither is set/valid.
func (c *Config) Resolve(explicit string) *model.Profile {
	name := explicit
	if name == "" {
		name = c.Default
	}
	if name == "" {
		return nil
	}
	if p, ok := c.Profiles[name]; ok {
		return &p
	}
	return nil
}

func parse(data []byte) (*Config, error) {
	tree, err := parseYAML(string(data))
	if err != nil {
		return nil, err
	}
	cfg := &Config{Profiles: map[string]model.Profile{}, Default: str(tree["default_profile"])}
	profiles := asMap(tree["profiles"])
	if profiles == nil {
		return nil, fmt.Errorf("config: missing top-level `profiles:` map")
	}
	for _, name := range profiles.order {
		pm := asMap(profiles.m[name])
		if pm == nil {
			continue
		}
		git := asMap(pm.m["git"])
		aws := asMap(pm.m["aws"])
		kube := asMap(pm.m["kube"])
		ssh := asMap(pm.m["ssh"])
		p := model.Profile{Name: name}
		if git != nil {
			p.Git = model.GitExpect{
				Name:       str(git.m["name"]),
				Email:      str(git.m["email"]),
				SigningKey: str(git.m["signingkey"]),
			}
		}
		if aws != nil {
			p.AWS = model.AWSExpect{Profile: str(aws.m["profile"])}
		}
		if kube != nil {
			p.Kube = model.KubeExpect{
				Context:   str(kube.m["context"]),
				Namespace: str(kube.m["namespace"]),
			}
		}
		if ssh != nil {
			p.SSH = model.SSHExpect{Key: str(ssh.m["key"])}
		}
		cfg.Profiles[name] = p
		cfg.Order = append(cfg.Order, name)
	}
	if len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("config: no profiles defined")
	}
	if cfg.Default != "" {
		if _, ok := cfg.Profiles[cfg.Default]; !ok {
			return nil, fmt.Errorf("config: default_profile %q is not defined", cfg.Default)
		}
	}
	return cfg, nil
}

// WriteExample writes a starter config (idctl's own file); refuses to clobber.
func WriteExample() (string, error) {
	if err := os.MkdirAll(Dir(), 0o755); err != nil {
		return "", err
	}
	p := ConfigPath()
	if _, err := os.Stat(p); err == nil {
		return p, fmt.Errorf("config already exists at %s", p)
	}
	return p, os.WriteFile(p, []byte(exampleConfig), 0o644)
}

const exampleConfig = `# idctl config -- declare the identity profiles you compare against.
# idctl is read-only: it never changes git/aws/kube/ssh, it only reports.
# Only the fields you set are checked; omit anything you don't care about.

# Optional: which profile status/doctor compare against when no --profile flag
# is given.
default_profile: personal

profiles:
  personal:
    git:
      name: "Your Name"
      email: you@personal.dev
    aws:
      profile: default
    kube:
      context: minikube
    ssh:
      key: ~/.ssh/id_personal

  work:
    git:
      name: "Your Name"
      email: you@company.com
      signingkey: ABCD1234EF567890
    aws:
      profile: work-sso
    kube:
      context: work-eks
      namespace: team-a
    ssh:
      key: ~/.ssh/id_work
`
