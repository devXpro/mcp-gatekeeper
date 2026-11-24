import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** cn joins class names and lets later Tailwind utilities override earlier ones (shadcn/ui's helper). */
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}
