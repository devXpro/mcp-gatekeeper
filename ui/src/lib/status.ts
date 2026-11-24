// Status tones (DESIGN.md §10): a colour for a state. An application maps its own states onto them (Family Hub: a
// service's look, a module's state).

export type Tone = 'success' | 'warning' | 'danger' | 'gray'

export const TONE_BG: Record<Tone, string> = {
  success: 'bg-success',
  warning: 'bg-warning',
  danger: 'bg-danger',
  gray: 'bg-gray',
}

/** TONE_STATUS sets --status for the hero glow (index.css). */
export const TONE_STATUS: Record<Tone, string> = {
  success: 'fh-status-success',
  warning: 'fh-status-warning',
  danger: 'fh-status-danger',
  gray: 'fh-status-gray',
}
