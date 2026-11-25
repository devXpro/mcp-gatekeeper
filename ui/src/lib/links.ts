/**
 * safeNext keeps a return path inside the SPA, so ?next= cannot send the person elsewhere. Without a usable one it is
 * "/": the shell's index route decides where a signed-in person starts (an application's indexRoute, else /connect).
 */
export function safeNext(v: string | null) {
  if (!v || !v.startsWith('/') || v.startsWith('//') || v.includes('\\') || v.startsWith('/login')) return '/'
  return v
}
