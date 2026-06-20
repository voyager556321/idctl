package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/voyager556321/idctl/internal/config"
	"github.com/voyager556321/idctl/internal/engine"
	"github.com/voyager556321/idctl/internal/model"
	"github.com/voyager556321/idctl/internal/predictor"
)

func cmdPredict(args []string) int {
	fs := flag.NewFlagSet("predict", flag.ContinueOnError)
	profile := fs.String("profile", "", "expected profile to compare against (default: config default_profile)")
	action := fs.String("action", "", "predict only one action: git-commit|git-push|aws|kubectl|ssh")
	verify := fs.Bool("verify", false, "perform the online AWS STS read (slower)")
	quiet := fs.Bool("quiet", false, "print nothing on low/medium; only warn on HIGH (for shell hooks)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx := context.Background()
	id := engine.ReadAll(ctx)
	if *verify {
		engine.VerifyAWS(ctx, id)
	}

	var expected *model.Profile
	var expectedName string
	var all map[string]model.Profile
	if cfg, err := config.Load(); err == nil {
		all = cfg.Profiles
		expected = cfg.Resolve(*profile)
		if expected != nil {
			expectedName = expected.Name
		}
	} else if *profile != "" {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var risks []predictor.ActionRisk
	if *action != "" {
		r, ok := predictor.PredictOne(id, expected, all, *action)
		if !ok {
			fmt.Fprintf(os.Stderr, "unknown action %q (use git-commit|git-push|aws|kubectl|ssh)\n", *action)
			return 2
		}
		risks = []predictor.ActionRisk{r}
	} else {
		risks = predictor.Predict(id, expected, all)
	}

	overall := predictor.MaxRisk(risks)

	// Quiet mode: only speak up on HIGH; otherwise stay silent (hook-friendly).
	if *quiet {
		if overall >= model.RiskHigh {
			for _, r := range risks {
				if r.RiskLevel >= model.RiskHigh {
					fmt.Fprintf(os.Stderr, "%s %s: %s\n", symbol(r.RiskLevel), r.Action, r.Explanation)
				}
			}
		}
		return exitForRisk(overall)
	}

	renderPredict(os.Stdout, risks, expectedName)
	return exitForRisk(overall)
}

func renderPredict(w *os.File, risks []predictor.ActionRisk, expectedName string) {
	hdr := bold("NEXT ACTION RISKS")
	if expectedName != "" {
		hdr += dim("  (vs profile: " + expectedName + ")")
	} else {
		hdr += dim("  (no expected profile set)")
	}
	fmt.Fprintf(w, "\n  %s\n\n", hdr)
	for _, r := range risks {
		sym := riskColor(r.RiskLevel, symbol(r.RiskLevel))
		fmt.Fprintf(w, "  %s  %-14s %s\n", sym, r.Action, r.Subject)
		fmt.Fprintf(w, "      %s\n", dim(r.Explanation))
	}
}

func symbol(r model.Risk) string {
	switch r {
	case model.RiskHigh:
		return "X" // rendered red
	case model.RiskMedium, model.RiskLow:
		return "!"
	default:
		return "+"
	}
}

// exitForRisk: 3 high / 2 medium / 1 low / 0 none. Lets hooks branch on $?.
func exitForRisk(r model.Risk) int {
	switch r {
	case model.RiskHigh:
		return 3
	case model.RiskMedium:
		return 2
	case model.RiskLow:
		return 1
	default:
		return 0
	}
}
