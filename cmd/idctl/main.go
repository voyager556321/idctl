// Command idctl is a lightweight runtime identity-state inspector and fixer.
// It reads (never stores) your git / aws / kubectl / ssh identity, normalises
// it, detects mismatches against a configured profile, and can switch profiles.
package main

import (
	"os"

	"github.com/voyager556321/idctl/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
