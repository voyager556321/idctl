// Package model defines the unified identity state and the desired-state
// (profile) types that every adapter reads into and diffs against.
package model

// Risk is the severity of a single finding.
type Risk int

const (
	RiskNone Risk = iota
	RiskLow
	RiskMedium
	RiskHigh
)

func (r Risk) String() string {
	switch r {
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	default:
		return "none"
	}
}

// ---------------------------------------------------------------------------
// Observed system state. Each adapter owns one slice of Identity.
// ---------------------------------------------------------------------------

type GitState struct {
	Present        bool // git binary found
	InRepo         bool
	GlobalName     string
	GlobalEmail    string
	RepoName       string // local override (empty if none)
	RepoEmail      string
	EffectiveName  string // what git actually uses right now
	EffectiveEmail string
	SigningKey     string
	GpgSign        bool
	RemoteURL      string // origin URL (empty if none)
	RemoteHost     string // host parsed from origin
	RemoteProto    string // "ssh" | "https" | "" (unknown)
}

type AWSState struct {
	Present  bool   // aws cli found (only needed for --verify)
	Profile  string // resolved profile name
	Source   string // "env" | "default"
	Account  string // populated only when Verified
	Arn      string
	Verified bool
}

type KubeState struct {
	Present   bool // kubectl found
	Context   string
	Namespace string
}

type SSHKey struct {
	Fingerprint string
	Comment     string
	Type        string
}

type SSHState struct {
	Present    bool // ssh-agent reachable
	AgentEmpty bool
	AgentKeys  []SSHKey
}

// Identity is the in-memory unified model assembled from all adapters.
type Identity struct {
	Git  GitState
	AWS  AWSState
	Kube KubeState
	SSH  SSHState
}

// ---------------------------------------------------------------------------
// Desired state, loaded from ~/.idctl/config.yaml
// ---------------------------------------------------------------------------

type GitExpect struct {
	Name       string
	Email      string
	SigningKey string
}

type AWSExpect struct{ Profile string }

type KubeExpect struct {
	Context   string
	Namespace string
}

type SSHExpect struct{ Key string } // path to a private key

type Profile struct {
	Name string
	Git  GitExpect
	AWS  AWSExpect
	Kube KubeExpect
	SSH  SSHExpect
}

// Mismatch is one difference between observed state and the active profile.
type Mismatch struct {
	Adapter  string
	Field    string
	Current  string
	Expected string
	Risk     Risk
	// Explain is a short human sentence used by `doctor`.
	Explain string
}
