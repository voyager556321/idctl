package cli

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/voyager556321/idctl/internal/config"
	"github.com/voyager556321/idctl/internal/engine"
	"github.com/voyager556321/idctl/internal/model"
	"github.com/voyager556321/idctl/internal/risk"
)

func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	profile := fs.String("profile", "", "expected profile to compare against (default: config default_profile)")
	offline := fs.Bool("offline", false, "skip the online AWS STS read")
	verbose := fs.Bool("verbose", false, "show expected/current values for each finding")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ctx := context.Background()
	id := engine.ReadAll(ctx)
	if !*offline {
		engine.VerifyAWS(ctx, id)
	}

	var expected *model.Profile
	var expectedName string
	if cfg, err := config.Load(); err == nil {
		expected = cfg.Resolve(*profile)
		if expected != nil {
			expectedName = expected.Name
		}
	} else if *profile != "" {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	findings := risk.Analyze(id, expected)
	renderFindings(os.Stdout, findings, expectedName, *verbose, "idctl doctor")
	return exitForRisk(risk.MaxRisk(findings))
}
