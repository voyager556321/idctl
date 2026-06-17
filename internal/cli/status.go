package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"idctl/internal/config"
	"idctl/internal/engine"
	"idctl/internal/model"
)

func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	profile := fs.String("profile", "", "expected profile to compare against (default: config default_profile)")
	verify := fs.Bool("verify", false, "perform the online AWS STS read (slower)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx := context.Background()
	id := engine.ReadAll(ctx)
	if *verify {
		engine.VerifyAWS(ctx, id)
	}

	var p *model.Profile
	var expectedName string
	if cfg, err := config.Load(); err == nil {
		p = cfg.Resolve(*profile)
		if p != nil {
			expectedName = p.Name
		}
	} else if *profile != "" {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var mm []model.Mismatch
	if p != nil {
		mm = engine.DiffAll(id, p)
	}

	w := os.Stdout
	if expectedName == "" {
		fmt.Fprintln(w, dim("\n  no expected profile (set default_profile or pass --profile); showing raw state"))
	} else {
		fmt.Fprintf(w, "\n  comparing against profile: %s\n", bold(expectedName))
	}

	renderStatus(w, id, mm)

	if len(mm) > 0 {
		fmt.Fprintf(w, "\n  %s %d mismatch(es) -- run `idctl doctor` for detail\n",
			yellow("!"), len(mm))
		return 1
	}
	if p != nil {
		fmt.Fprintf(w, "\n  %s everything matches profile %q\n", green("ok"), expectedName)
	}
	return 0
}

func renderStatus(w *os.File, id *model.Identity, mm []model.Mismatch) {
	g := id.Git
	section(w, "git")
	if !g.Present {
		fmt.Fprintln(w, dim("    git not found"))
	} else {
		row(w, "name", g.EffectiveName, mismatchFor(mm, "git", "name"))
		row(w, "email", g.EffectiveEmail, mismatchFor(mm, "git", "email"))
		if g.SigningKey != "" || mismatchFor(mm, "git", "signingkey") != nil {
			row(w, "signingkey", g.SigningKey, mismatchFor(mm, "git", "signingkey"))
		}
		scope := "global"
		if g.InRepo {
			scope = "repo (local override active)"
			if g.RepoEmail == "" {
				scope = "repo (using global)"
			}
		}
		fmt.Fprintf(w, "    %-12s %s\n", "scope", dim(scope))
	}

	a := id.AWS
	section(w, "aws")
	row(w, "profile", fmt.Sprintf("%s [%s]", a.Profile, a.Source), mismatchFor(mm, "aws", "profile"))
	if a.Verified {
		fmt.Fprintf(w, "    %-12s %s\n", "account", dim(a.Account))
		fmt.Fprintf(w, "    %-12s %s\n", "arn", dim(a.Arn))
	}

	k := id.Kube
	section(w, "kubectl")
	if !k.Present {
		fmt.Fprintln(w, dim("    kubectl not found"))
	} else {
		row(w, "context", k.Context, mismatchFor(mm, "kubectl", "context"))
		row(w, "namespace", k.Namespace, mismatchFor(mm, "kubectl", "namespace"))
	}

	s := id.SSH
	section(w, "ssh")
	if !s.Present {
		fmt.Fprintln(w, dim("    ssh-agent not available"))
	} else if s.AgentEmpty {
		row(w, "agent", "(no keys loaded)", mismatchFor(mm, "ssh", "key"))
	} else {
		for i, key := range s.AgentKeys {
			label := "key"
			if i > 0 {
				label = ""
			}
			cm := key.Comment
			if key.Type != "" {
				cm = fmt.Sprintf("%s (%s)", key.Comment, key.Type)
			}
			fmt.Fprintf(w, "    %-12s %s\n", label, val(cm))
		}
		if m := mismatchFor(mm, "ssh", "key"); m != nil {
			fmt.Fprintf(w, "    %-12s %s %s\n", "", riskColor(m.Risk, "MISMATCH"),
				dim("expected key "+m.Expected))
		}
	}
}
