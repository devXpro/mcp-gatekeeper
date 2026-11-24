import { ShieldCheck } from 'lucide-react'
import type { Brand } from '../config'

/** The tests' brand: names of its own, so the tests prove they come from the brand and not from Family Hub. */
export const TEST_BRAND: Brand = { csrfHeader: 'X-Gatekeeper-Test', storagePrefix: 'gk-test', icon: ShieldCheck }
