// TanStack Query hooks for every GET of the gatekeeper's API (DESIGN.md §7): staleTime 10 s, refetch on focus,
// previous data kept while refetching. Errors that the API words (ApiError) are not retried. An application adds its
// own keys next to `qk` (Family Hub: setup, status, the deployer's).

import { keepPreviousData, QueryClient, useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { api, ApiError, OfflineError, seg } from './api'
import type { Account, AdminAccount, AuditEntry, Connection, ConsentTxn, Me, Passkey } from './types'

export function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10_000,
        refetchOnWindowFocus: true,
        retry: (n, err) => !(err instanceof ApiError) && !(err instanceof OfflineError) && n < 1,
      },
      mutations: { retry: false },
    },
  })
}

export const qk = {
  me: ['me'] as const,
  account: ['account'] as const,
  connections: ['connections'] as const,
  passkeys: ['passkeys'] as const,
  accountAudit: ['audit', 'account'] as const,
  txn: (txn: string) => ['txn', txn] as const,
  adminAccounts: ['admin', 'accounts'] as const,
  adminAudit: ['audit', 'admin'] as const,
}

export function useMe(enabled = true) {
  return useQuery({ queryKey: qk.me, queryFn: () => api.get<Me>('/me'), enabled, staleTime: 60_000 })
}

/** useAccount reads GET /api/account; an application reads its own fields with a wider type (useAccount<T>()). */
export function useAccount<T extends Account = Account>() {
  return useQuery({ queryKey: qk.account, queryFn: () => api.get<T>('/account') })
}

export function useConnections() {
  return useQuery({ queryKey: qk.connections, queryFn: async () => (await api.get<Connection[] | null>('/account/connections')) ?? [] })
}

export function usePasskeys() {
  return useQuery({ queryKey: qk.passkeys, queryFn: async () => (await api.get<Passkey[] | null>('/me/passkeys')) ?? [] })
}

export function useTxn(txn: string) {
  return useQuery({
    queryKey: qk.txn(txn),
    queryFn: () => api.get<ConsentTxn>(`/oauth/txn/${seg(txn)}`),
    enabled: txn !== '',
    staleTime: Infinity,
    refetchOnWindowFocus: false,
  })
}

export function useAdminAccounts() {
  return useQuery({ queryKey: qk.adminAccounts, queryFn: async () => (await api.get<AdminAccount[] | null>('/admin/accounts')) ?? [] })
}

export const AUDIT_PAGE = 50

/** auditList accepts a bare array or an object holding one ({entries} or {items}). */
function auditList(v: unknown): AuditEntry[] {
  if (Array.isArray(v)) return v as AuditEntry[]
  if (v && typeof v === 'object') {
    const o = v as { entries?: unknown; items?: unknown }
    if (Array.isArray(o.entries)) return o.entries as AuditEntry[]
    if (Array.isArray(o.items)) return o.items as AuditEntry[]
  }
  return []
}

/** useAudit pages the account's (or, for the superadmin, the system's) audit log by `before`. */
export function useAudit(scope: 'account' | 'admin') {
  return useInfiniteQuery({
    queryKey: scope === 'account' ? qk.accountAudit : qk.adminAudit,
    queryFn: async ({ pageParam }) =>
      auditList(await api.get<unknown>(scope === 'account' ? '/account/audit' : '/admin/audit', { query: { before: pageParam, limit: AUDIT_PAGE } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => (last.length < AUDIT_PAGE ? undefined : last[last.length - 1]?.id),
    placeholderData: keepPreviousData,
  })
}
