package auth

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/devXpro/mcp-gatekeeper/adminsock"
	"github.com/devXpro/mcp-gatekeeper/core"
)

// ResetStep is an application's part of reset-access: it ends what one superadmin's identity left behind in the
// application's own data (Family Hub: the superadmin's legacy Site keys). Run is called for every superadmin inside
// reset-access's transaction (ctx carries it), after their passkeys, sessions and OAuth grants and before their open
// invites; it returns how many things it ended, and an error rolls the whole reset back. Its count goes into the
// audit detail under Key and into the printed summary as "<n> <Phrase>".
type ResetStep struct {
	Key    string // e.g. "legacy_keys"
	Phrase string // e.g. "legacy keys"
	Run    func(ctx context.Context, p core.Person, now time.Time) (int, error)
}

// resetKeys are the audit detail keys of reset-access itself.
var resetKeys = []string{"people", "passkeys", "grants", "invites"}

// checkSteps refuses a step without Run, a phrase or a key, or with a key taken.
func checkSteps(steps []ResetStep) error {
	seen := map[string]bool{}
	for _, k := range resetKeys {
		seen[k] = true
	}
	for _, s := range steps {
		switch {
		case s.Run == nil || s.Key == "" || s.Phrase == "":
			return fmt.Errorf("auth: reset step %q needs a key, a phrase and a Run", s.Key)
		case seen[s.Key]:
			return fmt.Errorf("auth: reset step key %q is taken", s.Key)
		}
		seen[s.Key] = true
	}
	return nil
}

// AdminCommands are auth's admin commands; New adds them to Options.Admin when it is set.
//
//	setup-link    a one-time link that registers the superadmin's passkey: with no superadmin yet it creates the
//	              first account and its superadmin owner; after reset-access it adds a passkey to the superadmin.
//	              Refused while an enabled superadmin has a passkey.
//	reset-access  wipes every passkey and session of the superadmin, revokes their OAuth grants, runs the
//	              application's ResetSteps (Family Hub: deletes their legacy keys) and revokes the invites they made,
//	              revokes the older setup links and prints a new one; then Options.OnAccessReset hears of it.
//
// The links are printed to the operator's terminal only, never logged. Both commands audit the socket's peer (its pid
// and executable, and who started it: adminsock.Peer) when the socket knew it.
func (a *Auth) AdminCommands() []adminsock.Command {
	return []adminsock.Command{
		{Name: "setup-link", Summary: "print a one-time link that registers the superadmin's passkey", Run: a.cmdSetupLink},
		{Name: "reset-access", Summary: "wipe the superadmin's passkeys, sessions, connectors and invites and print a new setup link",
			Run: a.cmdResetAccess},
	}
}

func noArgs(name string, inv adminsock.Invocation) error {
	if len(inv.Args) > 0 {
		return fmt.Errorf("%w: %s takes no arguments", adminsock.ErrUsage, name)
	}
	return nil
}

func (a *Auth) cmdSetupLink(ctx context.Context, inv adminsock.Invocation) error {
	if err := noArgs("setup-link", inv); err != nil {
		return err
	}
	detail, attrs := peerDetail(inv.Peer)
	url, expires, err := a.issueSetupLink(ctx, SetupLinkTTL, "on the admin socket", detail, attrs)
	if err != nil {
		return err
	}
	return a.printLink(inv.Out, url, expires)
}

// peerDetail is the socket peer for an audit entry's detail (peer_pid, peer_exe and, when known, peer_chain) and a log
// line, when the socket knew it (review GK-5: on a desktop every program of the same user reaches the socket, so the
// audit names which one; the peer is usually the application's own CLI, so peer_chain names who started it).
func peerDetail(p adminsock.Peer) (map[string]string, []any) {
	if p.PID <= 0 {
		return map[string]string{}, nil
	}
	detail := map[string]string{"peer_pid": strconv.Itoa(p.PID), "peer_exe": p.Exe}
	attrs := []any{slog.Int("peer_pid", p.PID), slog.String("peer_exe", p.Exe)}
	if p.Chain != "" {
		detail["peer_chain"] = p.Chain
		attrs = append(attrs, slog.String("peer_chain", p.Chain))
	}
	return detail, attrs
}

// AccessReset is what Options.OnAccessReset learns after reset-access: when, whose access was wiped (the
// superadmins; empty on an application nobody has set up), and the socket peer that asked (adminsock.Peer: its pid,
// executable and ancestors, when known).
type AccessReset struct {
	At     time.Time
	People []core.PersonID
	Peer   adminsock.Peer
}

func (a *Auth) cmdResetAccess(ctx context.Context, inv adminsock.Invocation) error {
	if err := noArgs("reset-access", inv); err != nil {
		return err
	}
	now := a.now()
	var (
		people  []core.Person
		total   resetCounts
		url     string
		expires time.Time
	)
	err := a.st.Tx(ctx, func(ctx context.Context) error {
		people, total = nil, a.newResetCounts()
		sas, err := superadmins(ctx, a.st)
		if err != nil {
			return err
		}
		for _, p := range sas {
			n, err := a.resetPerson(ctx, p, now)
			if err != nil {
				return err
			}
			people, total = append(people, p), total.add(n)
		}
		url, expires, err = a.newSetupLink(ctx, now, SetupLinkTTL)
		return err
	})
	if err != nil {
		return err
	}
	detail, peerAttrs := peerDetail(inv.Peer)
	detail["people"], detail["passkeys"] = strconv.Itoa(len(people)), strconv.Itoa(total.passkeys)
	detail["grants"], detail["invites"] = strconv.Itoa(total.grants), strconv.Itoa(total.invites)
	attrs := []any{slog.Int("people", len(people)), slog.Int("passkeys", total.passkeys), slog.Int("grants", total.grants)}
	for i, s := range a.steps {
		detail[s.Key] = strconv.Itoa(total.steps[i])
		attrs = append(attrs, slog.Int(s.Key, total.steps[i]))
	}
	attrs = append(append(attrs, slog.Int("invites", total.invites)), peerAttrs...)
	a.audit(ctx, core.AuditEntry{At: now, Action: "admin.reset-access", Detail: detail})
	a.log.Info("auth: access was reset on the admin socket", attrs...)
	if a.onReset != nil {
		ids := make([]core.PersonID, 0, len(people))
		for _, p := range people {
			ids = append(ids, p.ID)
		}
		a.onReset(context.WithoutCancel(ctx), AccessReset{At: now, People: ids, Peer: inv.Peer})
	}
	if len(people) == 0 {
		if _, err := fmt.Fprintf(inv.Out, "The %s has no superadmin yet: nothing to wipe.\n", a.brand.AppWord()); err != nil {
			return err
		}
	}
	for _, p := range people {
		if _, err := fmt.Fprintf(inv.Out, "Wiped the passkeys and sessions of %s (%s).\n", p.Name, p.ID); err != nil {
			return err
		}
	}
	if len(people) > 0 {
		if _, err := fmt.Fprintf(inv.Out, "Ended %s.\n", a.summary(total)); err != nil {
			return err
		}
	}
	return a.printLink(inv.Out, url, expires)
}

// summary lists what reset-access ended: "1 passkeys, 0 connectors (OAuth grants), 2 legacy keys and 0 open invites".
func (a *Auth) summary(total resetCounts) string {
	parts := []string{fmt.Sprintf("%d passkeys", total.passkeys), fmt.Sprintf("%d connectors (OAuth grants)", total.grants)}
	for i, s := range a.steps {
		parts = append(parts, fmt.Sprintf("%d %s", total.steps[i], s.Phrase))
	}
	parts = append(parts, fmt.Sprintf("%d open invites", total.invites))
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// resetCounts is what reset-access ended for one superadmin, or for all of them; steps follow Options.ResetSteps.
type resetCounts struct {
	passkeys, grants, invites int
	steps                     []int
}

func (a *Auth) newResetCounts() resetCounts { return resetCounts{steps: make([]int, len(a.steps))} }

func (r resetCounts) add(o resetCounts) resetCounts {
	out := resetCounts{passkeys: r.passkeys + o.passkeys, grants: r.grants + o.grants, invites: r.invites + o.invites,
		steps: make([]int, len(r.steps))}
	for i := range out.steps {
		out.steps[i] = r.steps[i] + o.steps[i]
	}
	return out
}

// resetPerson ends everything an attacker who held p's passkey or session could have left behind (T2.R M3): p's
// passkeys and sessions, p's OAuth grants with their tokens, what the application's ResetSteps end, and the open
// invites p made in any account. People who already joined through p's invites stay; the owner or the superadmin
// removes them. ctx carries the transaction of reset-access.
func (a *Auth) resetPerson(ctx context.Context, p core.Person, now time.Time) (resetCounts, error) {
	st := a.st
	n := a.newResetCounts()
	pks, err := st.Passkeys().ListByPerson(ctx, p.ID)
	if err != nil {
		return n, err
	}
	n.passkeys = len(pks)
	if err := st.Passkeys().DeleteByPerson(ctx, p.ID); err != nil {
		return n, err
	}
	if err := st.Sessions().DeleteByPerson(ctx, p.ID); err != nil {
		return n, err
	}
	grants, err := st.OAuth().ListGrantsByAccount(ctx, p.AccountID)
	if err != nil {
		return n, err
	}
	for _, g := range grants {
		if g.PersonID != p.ID || g.RevokedAt != nil {
			continue
		}
		if err := st.OAuth().RevokeGrant(ctx, g.ID, now); err != nil {
			return n, err
		}
		n.grants++
	}
	for i, s := range a.steps {
		c, err := s.Run(ctx, p, now)
		if err != nil {
			return n, err
		}
		n.steps[i] = c
	}
	accounts, err := st.Accounts().List(ctx)
	if err != nil {
		return n, err
	}
	for _, acc := range accounts {
		invs, err := st.Invites().ListByAccount(ctx, acc.ID)
		if err != nil {
			return n, err
		}
		for _, inv := range invs {
			if inv.CreatedBy != p.ID || inv.UsedAt != nil || inv.RevokedAt != nil || !inv.ExpiresAt.After(now) {
				continue
			}
			if err := st.Invites().Revoke(ctx, inv.ID, now); err != nil {
				return n, err
			}
			n.invites++
		}
	}
	return n, nil
}

func (a *Auth) printLink(w io.Writer, url string, expires time.Time) error {
	_, err := fmt.Fprintf(w, "The setup link works once, until %s (%s):\n\n  %s\n\n"+
		"Open it on the device that should hold the superadmin's passkey. Whoever opens it first takes the %s:\n"+
		"do not share it.\n", rfc3339(expires), SetupLinkTTL, url, a.brand.AppWord())
	return err
}
