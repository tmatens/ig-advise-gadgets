// Copyright 2026 The ig-advise-gadgets authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package advice

import (
	"fmt"
	"strings"
)

// The advice output is YAML that downstream tooling parses and applies to
// container privilege. Some rendered values are workload-controlled — a Linux
// path or device node may contain any byte except NUL and '/', including
// newlines and YAML metacharacters — so emitting them into a bare "  - %s"
// block-sequence entry lets a hostile container inject arbitrary YAML (a
// top-level `privileged: true`, an extra `cap_add:`, a `---` document break)
// and thereby make the advisor recommend MORE than the workload uses. Every
// such value MUST pass through yamlScalar before it reaches the output.

// safePlainByte reports whether c can appear in a path-like plain scalar that
// cannot be misparsed as anything but a string in block context.
func safePlainByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '/' || c == '.' || c == '_' || c == '-' || c == '+' || c == '@':
		return true
	default:
		return false
	}
}

// yamlScalar renders s as a YAML scalar that cannot break out of its node. A
// conservative path-like value is emitted as-is; anything else is double-quoted
// with control and quote characters escaped (YAML double-quoted scalars support
// \n, \r, \t and \xNN), so an embedded newline or `: ` can never start a new
// YAML node.
func yamlScalar(s string) string {
	safe := len(s) > 0 && s[0] != '-'
	for i := 0; safe && i < len(s); i++ {
		if !safePlainByte(s[i]) {
			safe = false
		}
	}
	if safe {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02X`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// commentText renders s for a single-line YAML comment (`# text`). A comment
// cannot be escaped, only a line break can break out of it, so control
// characters (newline, CR, and the rest) are replaced with spaces.
func commentText(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
