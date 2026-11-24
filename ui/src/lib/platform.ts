// The platform's passkey words and glyph (DESIGN.md §3.6): Face ID on iPhone and iPad, Touch ID on a Mac, a
// generic "passkey" elsewhere.

export type PasskeyKind = 'faceid' | 'touchid' | 'passkey'

interface UAData {
  platform?: string
  mobile?: boolean
}

function platformInfo() {
  const nav = typeof navigator === 'undefined' ? undefined : navigator
  const ua = nav?.userAgent ?? ''
  const uaData = (nav as (Navigator & { userAgentData?: UAData }) | undefined)?.userAgentData
  const platform = uaData?.platform ?? ''
  const touch = (nav?.maxTouchPoints ?? 0) > 1
  const iphone = /iPhone|iPod/.test(ua)
  // iPadOS reports itself as a Mac; the touch points give it away.
  const ipad = /iPad/.test(ua) || (/Macintosh/.test(ua) && touch)
  const mac = !ipad && (/Macintosh|Mac OS X/.test(ua) || platform === 'macOS')
  return { iphone, ipad, mac }
}

export function passkeyKind(): PasskeyKind {
  const p = platformInfo()
  if (p.iphone || p.ipad) return 'faceid'
  if (p.mac) return 'touchid'
  return 'passkey'
}
