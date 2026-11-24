/** Rich renders copy where `backticks` mark a command (DESIGN.md copy such as `hub admin setup-link`). */
export function Rich({ text }: { text: string }) {
  return (
    <>
      {text.split('`').map((part, i) =>
        i % 2 === 1 ? (
          <code key={i} className="rounded-xs bg-fill px-1 py-px font-mono text-[0.9em] whitespace-nowrap">
            {part}
          </code>
        ) : (
          part
        ),
      )}
    </>
  )
}
