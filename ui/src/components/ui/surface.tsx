import { createContext, useContext } from 'react'

/** Surface says whether content sits on a page or inside a sheet; cards and pressed rows differ (iOS elevation). */
export type Surface = 'page' | 'sheet'

export const SurfaceContext = createContext<Surface>('page')

export function useSurface() {
  return useContext(SurfaceContext)
}
