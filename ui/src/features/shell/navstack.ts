// In-app history: which path each history entry shows, so "‹ Back" pops when the previous entry is the parent
// (keeping the browser's own back and the iOS swipe in step) and pushes the parent otherwise. Also the last path
// visited in every tab, so switching tabs keeps each tab's own stack (DESIGN.md §2.3).

/** TabId is a tab's id: the gatekeeper's "connect" and "account", or an application's own. */
export type TabId = string

interface Entry {
  key: string
  pathname: string
}

let stack: Entry[] = []
let index = -1
const lastInTab = new Map<TabId, string>()

export function recordNavigation(type: 'PUSH' | 'POP' | 'REPLACE', key: string, pathname: string) {
  const entry = { key, pathname }
  if (type === 'PUSH' || index === -1) {
    stack = [...stack.slice(0, index + 1), entry]
    index = stack.length - 1
  } else if (type === 'REPLACE') {
    stack[index] = entry
  } else {
    const i = stack.findIndex((e) => e.key === key)
    if (i === -1) {
      stack = [entry]
      index = 0
    } else {
      index = i
    }
  }
}

/** previousIs says whether going back in the browser history lands on `pathname`. */
export function previousIs(pathname: string) {
  return index > 0 && stack[index - 1]?.pathname === pathname
}

export function rememberTabPath(tab: TabId, path: string) {
  lastInTab.set(tab, path)
}

export function tabPath(tab: TabId, root: string) {
  return lastInTab.get(tab) ?? root
}

/** canGoBack says whether the in-app history has an entry before this one. */
export function canGoBack() {
  return index > 0
}
