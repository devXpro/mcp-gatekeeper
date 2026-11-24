// Package actorname keeps the name of an audit entry's actor, as it was when the entry was written. core.AuditEntry
// has no field for it, so the name rides in Detail under one reserved key. The audit API reads it back as actor_name
// when the person is gone, and never shows it as a detail.
//
// An application that wants every entry named, whichever package writes it, wraps its store's Audit().Append with
// Stamp (Family Hub does).
package actorname

import (
	"context"
	"maps"

	"github.com/devXpro/mcp-gatekeeper/core"
	"github.com/devXpro/mcp-gatekeeper/store"
)

// Key is the reserved Detail key.
const Key = "actor_name"

// Stamp returns e with the actor's current name in Detail. An entry without an actor, one that already carries a
// name, or one whose actor cannot be read is returned as it is: an audit entry must never fail for a missing name.
// The caller's Detail map is not modified.
func Stamp(ctx context.Context, people store.PersonStore, e core.AuditEntry) core.AuditEntry {
	if e.Actor == "" {
		return e
	}
	if _, ok := e.Detail[Key]; ok {
		return e
	}
	p, err := people.Get(ctx, e.Actor)
	if err != nil || p.Name == "" {
		return e
	}
	detail := make(map[string]string, len(e.Detail)+1)
	maps.Copy(detail, e.Detail)
	detail[Key] = p.Name
	e.Detail = detail
	return e
}

// Split returns the stored name of e and its Detail without the reserved key (a new map, never nil).
func Split(e core.AuditEntry) (name string, detail map[string]string) {
	detail = make(map[string]string, len(e.Detail))
	for k, v := range e.Detail {
		if k == Key {
			name = v
			continue
		}
		detail[k] = v
	}
	return name, detail
}
