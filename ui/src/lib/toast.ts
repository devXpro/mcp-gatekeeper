// A tiny toast store (DESIGN.md §6 Toast): one line with an icon, 3 s, never for errors that need action.

export type ToastTone = 'success' | 'info' | 'warning'

export interface ToastItem {
  id: number
  text: string
  tone: ToastTone
}

type Listener = () => void

let items: ToastItem[] = []
let seq = 0
const listeners = new Set<Listener>()

function emit() {
  for (const l of listeners) l()
}

export function toast(text: string, tone: ToastTone = 'success') {
  const id = ++seq
  items = [...items.filter((t) => t.text !== text), { id, text, tone }].slice(-3)
  emit()
  setTimeout(() => dismissToast(id), 3000)
}

export function dismissToast(id: number) {
  const next = items.filter((t) => t.id !== id)
  if (next.length !== items.length) {
    items = next
    emit()
  }
}

export const toastStore = {
  subscribe(l: Listener) {
    listeners.add(l)
    return () => {
      listeners.delete(l)
    }
  },
  getSnapshot: () => items,
}
