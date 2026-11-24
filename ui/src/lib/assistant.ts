// The assistants an OAuth client can be (docs/PLAN.md §5.5: the redirect host tells ChatGPT from Claude).

export function assistantName(assistant: string, fallback = ''): string {
  if (assistant === 'chatgpt') return 'ChatGPT'
  if (assistant === 'claude') return 'Claude'
  return fallback || assistant
}
