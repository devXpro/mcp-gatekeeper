/** safeNext keeps a return path inside the SPA, so ?next= cannot send the person elsewhere. */
export function safeNext(v: string | null) {
  if (!v || !v.startsWith('/') || v.startsWith('//') || v.includes('\\') || v.startsWith('/login')) return '/connect'
  return v
}
