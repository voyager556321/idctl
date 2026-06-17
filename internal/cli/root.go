// Package cli implements the idctl command-line surface using only the
// standard library's flag package. idctl is a READ-ONLY diagnostic tool: the
// only mutating command is `init`, which scaffolds idctl's own config file and
// never touches git/aws/kube/ssh state.
package cli

import (
	"fmt"
	"os"

	"idctl/internal/config"
)

const usage = `idctl - read-only inspector for your runtime identity context

idctl reads (never changes) your git / aws / kubectl / ssh identity, normalises
it into one model, and reports mismatches against an expected profile.

USAGE
  idctl <command> [flags]

COMMANDS
  status [--profile NAME] [--verify]   show current identity + any mismatches
  risk [--profile NAME] [--verbose]    show only actionable findings, grouped by severity
  doctor [--profile NAME] [--offline]  analyse identity risks (same engine as risk)
  predict [--profile NAME] [--action A] predict the identity your NEXT git/aws/
                                        kubectl/ssh action will use, and its risk
  hook install [--with-aws] [--with-kubectl]
                                        print shell integration that warns before
                                        HIGH-risk actions (read-only; opt-in)
  profiles                             list configured profiles
  init                                 write a starter ~/.idctl/config.yaml
  help                                 show this message

The expected profile is chosen by --profile, else the config's default_profile.
Run 'idctl <command> -h' for command flags.`

// Main is the entry point; returns a process exit code.
func Main(args []string) int {
	if len(args) < 1 {
		fmt.Println(usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "status":
		return cmdStatus(rest)
	case "doctor":
		return cmdDoctor(rest)
	case "risk":
		return cmdRisk(rest)
	case "predict":
		return cmdPredict(rest)
	case "hook":
		return cmdHook(rest)
	case "profiles":
		return cmdProfiles(rest)
	case "init":
		return cmdInit(rest)
	case "help", "-h", "--help":
		fmt.Println(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s\n", cmd, usage)
		return 2
	}
}

func cmdProfiles(_ []string) int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Println(bold("configured profiles:"))
	for _, name := range cfg.Order {
		mark := "  "
		if name == cfg.Default {
			mark = green("* ")
		}
		p := cfg.Profiles[name]
		fmt.Printf("%s%-12s %s\n", mark, name,
			dim(fmt.Sprintf("git=%s aws=%s kube=%s", p.Git.Email, p.AWS.Profile, p.Kube.Context)))
	}
	if cfg.Default != "" {
		fmt.Printf("\n%s default (compared against unless --profile given): %s\n",
			green("*"), cfg.Default)
	}
	return 0
}

func cmdInit(_ []string) int {
	path, err := config.WriteExample()
	if err != nil {
		fmt.Fprintln(os.Stderr, "note:", err)
		return 1
	}
	fmt.Printf("%s wrote starter config to %s\n", green("ok"), path)
	fmt.Println(dim("  edit it to match your profiles, then run `idctl status`"))
	return 0
}
