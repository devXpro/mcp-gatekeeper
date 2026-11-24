import QRCode from 'qrcode'
import { useMemo } from 'react'

/**
 * QRCodeView draws a QR code as one SVG path (no canvas, no inline markup). It sits on a white card with black
 * modules in both themes: an inverted code (light on dark) scans less reliably on older phone cameras.
 */
export function QRCodeView({ value, size = 220, label }: { value: string; size?: number; label: string }) {
  const { path, n } = useMemo(() => {
    const qr = QRCode.create(value, { errorCorrectionLevel: 'M' })
    const count = qr.modules.size
    let d = ''
    for (let y = 0; y < count; y++) {
      for (let x = 0; x < count; x++) {
        if (qr.modules.get(y, x)) d += `M${x + 4} ${y + 4}h1v1h-1z`
      }
    }
    return { path: d, n: count + 8 }
  }, [value])
  return (
    <div className="inline-flex rounded-lg bg-white p-2 shadow-[0_0_0_0.5px_rgba(0,0,0,0.08)]">
      <svg role="img" aria-label={label} width={size} height={size} viewBox={`0 0 ${n} ${n}`} shapeRendering="crispEdges">
        <path d={path} fill="#000000" />
      </svg>
    </div>
  )
}
