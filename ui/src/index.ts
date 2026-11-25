// @devxpro/mcp-gatekeeper-ui: the admin web UI of MCP Gatekeeper as sources. See ui/README.md for how an application
// consumes it (configure(), <GatekeeperApp>, the Tailwind @source).

// Setup and the application's wiring
export { configure, type GatekeeperConfig } from './setup'
export { brand, features, storageKey, type Brand, type Features } from './config'
export { AppProvider, GatekeeperApp, type AppOptions, type GatekeeperAppProps } from './app/GatekeeperApp'
export { gatekeeperRoutes, type RouteOptions } from './app/routes'
export {
  AppContext,
  tabVisible,
  useApp,
  useLiveMode,
  type AppSlots,
  type CardSlotProps,
  type ConnectSlots,
  type LiveMode,
  type Resource,
  type ResourceTileProps,
  type TabDef,
} from './app/context'

// The design system (components/ui) and the shared components
export * from './components/ui/button'
export * from './components/ui/controls'
export * from './components/ui/copy'
export * from './components/ui/feedback'
export * from './components/ui/list'
export * from './components/ui/sheet'
export * from './components/ui/spinner'
export * from './components/ui/status'
export * from './components/ui/surface'
export { AppIcon, Avatar, IconTile, ResourceTile } from './components/ui/tile'
export * from './components/ui/toaster'
export * from './components/assistant'
export * from './components/invite'
export * from './components/page'
export * from './components/passkey'
export * from './components/rich'
// components/qrcode stays out of the barrel: InviteLink loads it lazily, so the QR library is its own chunk.

// The shared screens
export { AccountPage } from './features/account/AccountPage'
export { AppearancePage, LanguagePage } from './features/account/ChoicePages'
export { DeletePage } from './features/account/DeletePage'
export { Farewell } from './features/account/Farewell'
export { InviteSheet } from './features/account/InviteSheet'
export { PermissionPicker, TermPicker } from './features/account/AccessPickers'
export { MemberSheet, type MemberOpen } from './features/account/MemberSheet'
export { PasskeysPage } from './features/account/PasskeysPage'
export { FamiliesSection } from './features/admin/Families'
export { AccountAuditPage, AuditPage } from './features/audit/AuditPage'
export { LoginPage } from './features/auth/LoginPage'
export { Halo, Rise, SignInPanel } from './features/auth/SignIn'
export { StepUpProvider, useStepUp } from './features/auth/stepup'
export { CardDivider, ConnectPage } from './features/connect/ConnectPage'
export { ConsentPage } from './features/consent/ConsentPage'
export { NotFoundPage } from './features/misc/NotFound'
export { Onboarding } from './features/onboarding/Onboarding'
export { AdminOnly, AppShell, OfflineScreen, Splash, useLogout, type PageHandle } from './features/shell/AppShell'
export { DirectionContext } from './features/shell/direction'
export { canGoBack, previousIs, tabPath, type TabId } from './features/shell/navstack'
export { ACCOUNT_TAB, CONNECT_TAB, DEFAULT_TABS } from './features/shell/tabdefs'

// Strings
export { currentLang, default as i18n, detectLang, label, packageStrings, setLanguage, useLang, type Strings } from './i18n'

// Helpers
export * from './lib/access'
export * from './lib/api'
export * from './lib/assistant'
export * from './lib/clipboard'
export * from './lib/cn'
export * from './lib/consent'
export * from './lib/errors'
export * from './lib/format'
export * from './lib/hooks'
export * from './lib/links'
export * from './lib/motion'
export * from './lib/passkeys'
export * from './lib/platform'
export * from './lib/queries'
export * from './lib/status'
export * from './lib/theme'
export * from './lib/tiles'
export * from './lib/toast'
export type * from './lib/types'
