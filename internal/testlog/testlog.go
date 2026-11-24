// Package testlog captures slog records in tests (the gatekeeper's stand-in for zaptest/observer).
package testlog

import (
	"context"
	"log/slog"
	"strings"
	"sync"
)

// Record is one captured log record with its attributes flattened to strings.
type Record struct {
	Level   slog.Level
	Message string
	Attrs   map[string]string
}

// Recorder is a slog.Handler that keeps every record.
type Recorder struct {
	mu      *sync.Mutex
	records *[]Record
	attrs   []slog.Attr
	group   string
}

// New returns a logger and the recorder behind it.
func New() (*slog.Logger, *Recorder) {
	r := &Recorder{mu: &sync.Mutex{}, records: &[]Record{}}
	return slog.New(r), r
}

// Enabled implements slog.Handler: every level is kept.
func (r *Recorder) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements slog.Handler.
func (r *Recorder) Handle(_ context.Context, rec slog.Record) error {
	attrs := map[string]string{}
	add := func(a slog.Attr) {
		key := a.Key
		if r.group != "" {
			key = r.group + "." + key
		}
		attrs[key] = a.Value.Resolve().String()
	}
	for _, a := range r.attrs {
		add(a)
	}
	rec.Attrs(func(a slog.Attr) bool { add(a); return true })
	r.mu.Lock()
	defer r.mu.Unlock()
	*r.records = append(*r.records, Record{Level: rec.Level, Message: rec.Message, Attrs: attrs})
	return nil
}

// WithAttrs implements slog.Handler.
func (r *Recorder) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *r
	c.attrs = append(append([]slog.Attr{}, r.attrs...), attrs...)
	return &c
}

// WithGroup implements slog.Handler.
func (r *Recorder) WithGroup(name string) slog.Handler {
	c := *r
	if c.group != "" {
		name = c.group + "." + name
	}
	c.group = name
	return &c
}

// Records returns a copy of everything logged so far.
func (r *Recorder) Records() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Record(nil), (*r.records)...)
}

// Contains reports whether any record's message or attribute value contains s (for "never logs a secret" tests).
func (r *Recorder) Contains(s string) bool {
	for _, rec := range r.Records() {
		if strings.Contains(rec.Message, s) {
			return true
		}
		for _, v := range rec.Attrs {
			if strings.Contains(v, s) {
				return true
			}
		}
	}
	return false
}
