package main

import "unicode/utf8"

// truncRunes kort s in tot hooguit n tekens (runes), zonder UTF-8 te breken.
func truncRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	i := 0
	for p := range s {
		if i == n {
			return s[:p]
		}
		i++
	}
	return s
}

// truncBytes kort s in tot hooguit n bytes, op een tekengrens.
func truncBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return ""
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
