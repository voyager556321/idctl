package config

import (
	"fmt"
	"strings"
)

// omap is an insertion-ordered map, so profile listing is stable.
type omap struct {
	m     map[string]any
	order []string
}

func newOmap() *omap { return &omap{m: map[string]any{}} }

func (o *omap) set(k string, v any) {
	if _, ok := o.m[k]; !ok {
		o.order = append(o.order, k)
	}
	o.m[k] = v
}

func asMap(v any) *omap {
	if o, ok := v.(*omap); ok {
		return o
	}
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// parseYAML parses the supported subset:
//   - nested maps via 2-space (or any consistent) indentation
//   - "key:" opens a nested map; "key: value" assigns a scalar
//   - # comments (full-line and inline when preceded by a space)
//   - single/double quoted or bare scalar values
//
// It does NOT support: lists, multi-line scalars, anchors, flow style.
// That is sufficient for the idctl config schema and keeps the binary
// dependency-free.
func parseYAML(text string) (map[string]any, error) {
	root := newOmap()
	type frame struct {
		indent int
		node   *omap
	}
	stack := []frame{{indent: -1, node: root}}

	for n, raw := range strings.Split(text, "\n") {
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indent := countIndent(line)
		content := strings.TrimSpace(line)

		colon := strings.Index(content, ":")
		if colon < 0 {
			return nil, fmt.Errorf("line %d: expected `key:` or `key: value`, got %q", n+1, content)
		}
		key := strings.TrimSpace(content[:colon])
		val := strings.TrimSpace(content[colon+1:])

		// Unwind to the parent whose indent is strictly less than ours.
		for len(stack) > 1 && stack[len(stack)-1].indent >= indent {
			stack = stack[:len(stack)-1]
		}
		parent := stack[len(stack)-1].node

		if val == "" {
			child := newOmap()
			parent.set(key, child)
			stack = append(stack, frame{indent: indent, node: child})
		} else {
			parent.set(key, unquote(val))
		}
	}
	return root.m, nil
}

func countIndent(s string) int {
	i := 0
	for i < len(s) && s[i] == ' ' {
		i++
	}
	return i
}

// stripComment removes an inline/full-line comment, respecting quotes.
func stripComment(line string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			// Treat as comment if at start or preceded by whitespace.
			if i == 0 || line[i-1] == ' ' || line[i-1] == '\t' {
				return line[:i]
			}
		}
	}
	return line
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
