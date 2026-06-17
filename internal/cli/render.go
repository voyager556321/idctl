package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"idctl/internal/model"
)

// Color is disabled when NO_COLOR is set or stdout isn't a terminal-ish env.
var useColor = os.Getenv("NO_COLOR") == ""

func c(code, s string) string {
	if !useColor {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func bold(s string) string  { return c("1", s) }
func dim(s string) string   { return c("2", s) }
func green(s string) string { return c("32", s) }
func yellow(s string) string { return c("33", s) }
func red(s string) string   { return c("31", s) }

func riskColor(r model.Risk, s string) string {
	switch r {
	case model.RiskHigh:
		return red(s)
	case model.RiskMedium:
		return yellow(s)
	case model.RiskLow:
		return dim(s)
	default:
		return green(s)
	}
}

func val(s string) string {
	if s == "" {
		return dim("(unset)")
	}
	return s
}

// row prints "label: value" with a status marker and optional expected note.
func row(w io.Writer, label, current string, mm *model.Mismatch) {
	marker := green("ok")
	note := ""
	if mm != nil {
		marker = riskColor(mm.Risk, "MISMATCH")
		note = dim(fmt.Sprintf("  expected %s", val(mm.Expected)))
	}
	fmt.Fprintf(w, "    %-12s %-30s %s%s\n", label, val(current), marker, note)
}

func section(w io.Writer, title string) {
	fmt.Fprintf(w, "\n  %s\n", bold(title))
}

// mismatchFor finds the mismatch matching an adapter+field, if any.
func mismatchFor(ms []model.Mismatch, adapter, field string) *model.Mismatch {
	for i := range ms {
		if ms[i].Adapter == adapter && ms[i].Field == field {
			return &ms[i]
		}
	}
	return nil
}

func indent(s string, n int) string {
	pad := strings.Repeat(" ", n)
	return pad + strings.ReplaceAll(s, "\n", "\n"+pad)
}
