package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// tokenBytes is the entropy of session cookies, setup links and invites.
const tokenBytes = 32

// newToken returns a fresh secret: 32 random bytes as base64url without padding (43 characters).
func newToken() string {
	b := make([]byte, tokenBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b)
}

// hashToken is sha256(token), the only form a secret is stored in.
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// wellFormedToken reports whether s can be a token newToken made, so junk never reaches the store.
func wellFormedToken(s string) bool {
	if len(s) != base64.RawURLEncoding.EncodedLen(tokenBytes) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// MaxNameLen is the longest name of a person, an account or a passkey, in characters.
const MaxNameLen = 40

// ErrInvalidName is wrapped by NormalizeName's errors.
var ErrInvalidName = errors.New("invalid name")

// NormalizeName trims a display name (a person, an account, a passkey) and checks it: 1 to 40 characters, no control
// characters, no line or paragraph separators, no bidirectional controls, and no double quotes, backslashes or
// backticks. Names reach the identity claims modules get and the assistants' answers, where a line break or a quote
// could pass for an instruction of its own. T1.4 uses the same rule for its names.
func NormalizeName(v string) (string, error) {
	n, problem := checkName(v)
	if problem != "" {
		return "", fmt.Errorf("%w: it %s", ErrInvalidName, problem)
	}
	return n, nil
}

// checkName is NormalizeName with the problem as a phrase ("must be 1 to 40 characters"); "" means the name is fine.
func checkName(v string) (string, string) {
	v = strings.TrimSpace(v)
	if n := utf8.RuneCountInString(v); n < 1 || n > MaxNameLen {
		return "", fmt.Sprintf("must be 1 to %d characters", MaxNameLen)
	}
	if !utf8.ValidString(v) || strings.ContainsFunc(v, badNameRune) {
		return "", "must not contain control characters, line breaks, quotes, backslashes or backticks"
	}
	return v, ""
}

// Code points a name may not hold besides the control characters. They are numbers, not literals, so this file never
// carries a bidirectional control itself.
const (
	lineSeparator      = 0x2028
	paragraphSeparator = 0x2029
	bidiEmbedFirst     = 0x202a // LRE, RLE, PDF, LRO, RLO
	bidiEmbedLast      = 0x202e
	bidiIsolateFirst   = 0x2066 // LRI, RLI, FSI, PDI
	bidiIsolateLast    = 0x2069
	leftToRightMark    = 0x200e
	rightToLeftMark    = 0x200f
	arabicLetterMark   = 0x061c
)

func badNameRune(r rune) bool {
	switch {
	case unicode.IsControl(r), r == '"', r == '\\', r == '`', r == utf8.RuneError:
		return true
	case r == lineSeparator, r == paragraphSeparator, r == leftToRightMark, r == rightToLeftMark, r == arabicLetterMark:
		return true
	case r >= bidiEmbedFirst && r <= bidiEmbedLast, r >= bidiIsolateFirst && r <= bidiIsolateLast:
		return true
	}
	return false
}

// platforms name a passkey after the device that made it, when the client sent no name. Order matters: an iPad may say
// "Macintosh", every iPhone browser says "Mac OS X".
var platforms = []struct{ marker, name string }{
	{"iPhone", "iPhone"}, {"iPad", "iPad"}, {"Android", "Android"}, {"CrOS", "ChromeOS"},
	{"Macintosh", "Mac"}, {"Mac OS X", "Mac"}, {"Windows", "Windows"}, {"Linux", "Linux"},
}

// defaultPasskeyName is the platform in the User-Agent, or "Passkey".
func defaultPasskeyName(userAgent string) string {
	for _, p := range platforms {
		if strings.Contains(userAgent, p.marker) {
			return p.name
		}
	}
	return "Passkey"
}

// clip cuts s to at most n bytes without splitting a character.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
