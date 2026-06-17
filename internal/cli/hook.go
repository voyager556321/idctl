package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func cmdHook(args []string) int {
	if len(args) < 1 || args[0] != "install" {
		fmt.Fprintln(os.Stderr, "usage: idctl hook install [--with-aws] [--with-kubectl]")
		return 2
	}
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	withAWS := fs.Bool("with-aws", false, "also guard the `aws` command")
	withKube := fs.Bool("with-kubectl", false, "also guard the `kubectl` command")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	out := hookHeader + hookGuard + hookGit
	if *withAWS {
		out += hookAWS
	} else {
		out += commentBlock(hookAWS)
	}
	if *withKube {
		out += hookKube
	} else {
		out += commentBlock(hookKube)
	}
	out += hookFooter
	fmt.Print(out)
	return 0
}

func commentBlock(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		if line == "" {
			b.WriteString("\n")
			continue
		}
		b.WriteString("# " + line + "\n")
	}
	return b.String()
}

// The hook is read-only: it runs `idctl predict` before a command and only
// WARNS on HIGH risk. It never changes git/aws/kube/ssh state; on confirmation
// it simply runs the real command unchanged. Works in bash and zsh.

const hookHeader = `# ===== idctl shell hook =====
# Add with:  idctl hook install >> ~/.bashrc   (or ~/.zshrc)
# idctl never modifies anything; this only predicts identity risk and, on a
# HIGH-risk action, asks for confirmation before running the real command.

`

const hookGuard = `_idctl_guard() {
  # $1 = action key (git-commit|git-push|aws|kubectl|ssh)
  command idctl predict --action "$1" --quiet
  [ $? -lt 3 ] && return 0          # only HIGH (exit 3) blocks
  command idctl predict --action "$1"   # show the detail
  if [ -t 0 ]; then
    printf 'idctl: HIGH identity risk -- continue with %s? [y/N] ' "$1"
    read -r _idctl_ans
    case "$_idctl_ans" in
      [yY]*) return 0 ;;
      *) echo 'idctl: aborted'; return 1 ;;
    esac
  else
    echo 'idctl: HIGH identity risk (non-interactive shell; not blocking)' >&2
    return 0
  fi
}

`

const hookGit = `git() {
  case "$1" in
    commit) _idctl_guard git-commit || return 1 ;;
    push)   _idctl_guard git-push   || return 1 ;;
  esac
  command git "$@"
}

`

const hookAWS = `aws() {
  _idctl_guard aws || return 1
  command aws "$@"
}

`

const hookKube = `kubectl() {
  case "$1" in
    apply|delete|create|patch) _idctl_guard kubectl || return 1 ;;
  esac
  command kubectl "$@"
}

`

const hookFooter = `# ===== end idctl shell hook =====
`
