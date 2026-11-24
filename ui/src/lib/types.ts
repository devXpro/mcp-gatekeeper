// Wire types of the gatekeeper's JSON API (Family Hub docs/PLAN.md §5.9: auth, account, superadmin; §5.5: the consent
// API). Times are RFC 3339 strings. Go encodes empty slices as null, so every list a Go struct sends may be null. An
// application extends these with its own fields (Family Hub: `modules` on GET /api/account).

export type Lang = 'ru' | 'en'
export type Role = 'owner' | 'member'

// ---------------------------------------------------------------- auth

export interface MePerson {
  id: string
  name: string
  role: Role
  superadmin: boolean
}

export interface AccountRef {
  id: string
  name: string
}

/** GET /api/me */
export interface Me {
  person: MePerson
  account: AccountRef
  step_up_until?: string | null
}

export type InviteKind = 'setup' | 'owner' | 'member'

/** POST /api/auth/token */
export interface TokenInfo {
  kind: InviteKind
  name: string
  account_name?: string
}

/** The answer of every passkey "begin" call: WebAuthn options for the browser. */
export interface Begin {
  options: unknown
}

/** GET /api/me/passkeys */
export interface Passkey {
  id: string
  name: string
  created_at: string
  last_used_at?: string | null
}

// ---------------------------------------------------------------- account

export interface Member {
  id: string
  name: string
  role: Role
  joined_at: string
  you: boolean
}

export interface InviteRow {
  id: string
  name: string
  expires_at: string
}

/** GET /api/account; an application adds its own fields (Family Hub: `modules`). */
export interface Account {
  id: string
  name: string
  members: Member[] | null
  invites: InviteRow[] | null
}

/** POST /api/account/invites */
export interface CreatedInvite {
  id: string
  url: string
  expires_at: string
}

/**
 * GET /api/account/connections; `resource` is the resource id (an object with an id is accepted too). Besides the
 * OAuth grants an application may list standing keys, e.g. Family Hub's legacy keys of ChatGPT Sites
 * (docs/reviews/T2.R.md L2, T2.F5): `assistant: "site"`, a `label`, and an id `lk_…` (in `grant_id`; a bare `id` is
 * accepted too) that `DELETE /api/account/connections/{id}` takes.
 */
export interface Connection {
  grant_id: string
  id?: string
  resource: string | { id: string; name?: string }
  assistant: string
  client_name: string
  label?: string
  person: { id: string; name: string }
  created_at?: string | null
  last_used_at?: string | null
}

/** One audit line as the account and admin audit APIs send it. */
export interface AuditEntry {
  id: string
  at: string
  action: string
  actor?: string | { id: string; name?: string } | null
  actor_name?: string
  target?: string
  detail?: Record<string, string> | null
  ip?: string
}

// ---------------------------------------------------------------- consent (§5.5)

export interface ConsentTool {
  name: string
  title: string
  access: 'read' | 'write'
}

/** The resource (Family Hub: a module) an assistant asks for. */
export interface ConsentResource {
  id: string
  name: string
  description: string
  tools: ConsentTool[] | null
}

/**
 * GET /api/oauth/txn/{txn}. `started_from` and `client_kind` come with the H1 fix (docs/reviews/T2.R.md, T2.F1):
 * where the authorize request came from (the assistant's own page, `elsewhere` for a link opened by hand or from
 * another site) and whether the client registered itself (`dcr`, its name is self-declared) or is published by the
 * assistant (`cimd`).
 */
export interface ConsentTxn {
  assistant: string
  client_name: string
  redirect_host: string
  resource: ConsentResource
  account: AccountRef
  already_granted: boolean
  started_from?: 'assistant' | 'elsewhere' | 'unknown'
  client_kind?: 'dcr' | 'cimd'
}

/** approve and deny */
export interface Redirect {
  redirect_url: string
}

// ---------------------------------------------------------------- superadmin

export interface AdminAccount {
  id: string
  name: string
  /** a count, or the list itself */
  members: number | unknown[] | null
  /** an application's resources on in the account (Family Hub: modules): a count, or the list itself */
  modules?: number | unknown[] | null
  created_at: string
}

/** POST /api/admin/accounts */
export interface AdminAccountCreated {
  account: AccountRef
  invite: { url: string; expires_at: string }
}
