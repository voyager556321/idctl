package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/voyager556321/idctl/internal/config"
	"github.com/voyager556321/idctl/internal/engine"
	"github.com/voyager556321/idctl/internal/model"
	"github.com/voyager556321/idctl/internal/risk"
)

func cmdRisk(args []string) int {
	fs := flag.NewFlagSet("risk", flag.ContinueOnError)
	profile := fs.String("profile", "", "expected profile to compare against (default: config default_profile)")
	offline := fs.Bool("offline", false, "skip the online AWS STS read")
	verbose := fs.Bool("verbose", false, "show expected/current values and profile context")
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
	renderFindings(os.Stdout, findings, expectedName, *verbose, "idctl risk")
	return exitForRisk(risk.MaxRisk(findings))
}

// renderFindings prints actionable findings grouped by severity. Shared by risk and doctor.
func renderFindings(w io.Writer, findings []risk.Finding, expectedName string, verbose bool, header string) {
	fmt.Fprintf(w, "\n  %s\n", bold(header))
	if expectedName != "" {
		fmt.Fprintf(w, "  %s\n", dim("profile: "+expectedName))
	} else if verbose {
		fmt.Fprintf(w, "  %s\n", dim("(no expected profile — only profile-independent checks)"))
	}

	if len(findings) == 0 {
		fmt.Fprintf(w, "\n  %s no actionable risks\n", green("ok"))
		return
	}

	for _, group := range risk.BySeverity(findings) {
		fmt.Fprintf(w, "\n  %s\n", riskColor(group.Level, strings.ToUpper(group.Level.String())))
		for _, f := range group.Findings {
			fmt.Fprintf(w, "\n  %s\n", bold(f.Title))
			fmt.Fprintf(w, "    %s %s\n", dim("Problem:"), f.Problem)
			fmt.Fprintf(w, "    %s %s\n", dim("Impact:"), f.Impact)
			if f.Fix != "" {
				fmt.Fprintf(w, "    %s %s\n", dim("Fix:"), f.Fix)
			}
			if verbose {
				if f.Expected != "" {
					fmt.Fprintf(w, "    %s %s\n", dim("Expected:"), val(f.Expected))
				}
				if f.Current != "" {
					fmt.Fprintf(w, "    %s %s\n", dim("Current:"), val(f.Current))
				}
			}
		}
	}
	fmt.Fprintln(w)
}
