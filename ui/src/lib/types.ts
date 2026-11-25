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
  /** an owner invite into an account that has an owner already: the person joins it as a co-owner */
  co_owner?: boolean
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

/**
 * A person of the account. `access_until`, `permissions` and `active` come only from an application with a permission
 * catalog (people.Options.Permissions): the end of the person's access (null: none), the application's permission
 * ids ("all": everything) and whether the person may still sign in.
 */
export interface Member {
  id: string
  name: string
  role: Role
  joined_at: string
  you: boolean
  access_until?: string | null
  permissions?: string[] | null
  active?: boolean
}

export interface InviteRow {
  id: string
  name: string
  expires_at: string
  /** "owner" for a co-owner's invite (people.Options.CoOwners) */
  role?: Role
  access_until?: string | null
  permissions?: string[] | null
}

/**
 * One permission of the application's catalog (core.PermissionInfo): the invite sheet and the member detail show it
 * as a tick, under its group. A title or group may be a label map ({"ru": …, "en": …}).
 */
export interface PermissionInfo {
  id: string
  title: string | Record<string, string>
  group?: string | Record<string, string>
}

/** POST /api/account/invites; the access fields only with a catalog, `role` only with co-owners. */
export interface InviteBody {
  name: string
  access_until?: string
  permissions?: string[]
  role?: Role
}

/** PATCH /api/account/members/{id}: a field left out stays; access_until null removes the end. */
export interface MemberPatch {
  access_until?: string | null
  permissions?: string[]
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
