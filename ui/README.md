# @devxpro/mcp-gatekeeper-ui

The admin web UI of MCP Gatekeeper as **TypeScript/TSX sources**: the design system (tokens, typography,
`components/ui`), the shared components and the shared screens — sign-in, first-run setup and invites (`/setup`,
`/join`), consent, connect, account and people, passkeys, language and appearance, delete everything, the audit log,
the superadmin's families section, and the signed-in shell (tab bar on phones, sidebar on desktop) with slots for an
application's own tabs and routes. There is no build step and no npm registry: an application compiles the sources
with its own Vite.

## 1. Add the dependency

```jsonc
// package.json of the application
"dependencies": {
  "@devxpro/mcp-gatekeeper-ui": "github:devXpro/mcp-gatekeeper#v0.1.0", // a tag or a commit
  // the peers, at these versions or newer within the major:
  "@simplewebauthn/browser": "14.0.0",
  "@tanstack/react-query": "5.107.1",
  "class-variance-authority": "0.7.1",
  "clsx": "2.1.1",
  "i18next": "27.1.2",
  "lucide-react": "1.73.0",
  "motion": "14.14.0",
  "qrcode": "1.5.4",
  "react": "19.3.1",
  "react-dom": "19.3.1",
  "react-i18next": "18.0.1",
  "react-router": "8.5.1",
  "tailwind-merge": "3.7.0"
},
"devDependencies": { "tailwindcss": "4.3.5", "@tailwindcss/vite": "4.3.5", "@types/qrcode": "1.5.6" }
```

The libraries are peers so the application and the package share one React, one router, one i18next instance and
one TanStack Query client. npm installs only `ui/src` (no tests, no Go code).

## 2. TypeScript and Vite

The sources import each other with relative paths, so the application's own `@/` alias is untouched. The
application's `tsconfig` type-checks them like its own code and needs `"jsx": "react-jsx"`, `"moduleResolution":
"bundler"`, `"resolveJsonModule": true` and `"types": ["vite/client"]` (Family Hub's `tsconfig.app.json` has all of
them). Vite needs nothing special: `@vitejs/plugin-react` and `@tailwindcss/vite` as usual.

## 3. Tailwind

Import Tailwind first, then the package's stylesheet, and point Tailwind at the package's sources:

```css
/* src/styles/index.css of the application */
@import 'tailwindcss';
@import '@devxpro/mcp-gatekeeper-ui/styles.css';
@source '../../node_modules/@devxpro/mcp-gatekeeper-ui/ui/src';

/* the application's own styles follow */
```

The `@source` path is relative to the application's CSS file. (The package's stylesheet has its own `@source` too,
which current Tailwind honours; the application's line keeps it explicit.) The stylesheet defines the tokens
(`--bg`, `--label`, `--accent`, …, dark and light), the Tailwind theme built on them (the default palette is removed),
the `type-*`, `hairline-*`, `gutter-x` and `material` utilities, and the `fh-row`, `fh-skeleton`, `fh-spinner`,
`fh-halo-*` and `fh-status-*` classes. `./tokens.css` is exported on its own as well.

## 4. Configure, then render

```tsx
// src/main.tsx
import { configure, DEFAULT_TABS, GatekeeperApp } from '@devxpro/mcp-gatekeeper-ui'
import { HouseHeart, ShieldHalf } from 'lucide-react'
import { createRoot } from 'react-dom/client'
import './styles/index.css'
import en from './i18n/en.json'
import ru from './i18n/ru.json'

configure({
  // core.Brand.CSRFHeader of the Go side; the localStorage prefix ("fh.theme", "fh.lang"); the app icon's glyph
  brand: { csrfHeader: 'X-Family-Hub', storagePrefix: 'fh', icon: HouseHeart },
  // the application's strings: new keys and overrides of the package's (app.name, onboarding copy, …)
  strings: { ru, en },
})

createRoot(document.getElementById('root')!).render(
  <GatekeeperApp
    tabs={[...DEFAULT_TABS, { id: 'admin', root: '/admin', icon: ShieldHalf, label: 'tab.admin', superadmin: true }]}
    routes={[{ path: 'admin', lazy: async () => ({ Component: (await import('./admin')).AdminHome }), handle: { page: 'admin', tab: 'admin', depth: 0 } }]}
    resources={(account) => (account as MyAccount).modules ?? []}
    ResourceTile={ModuleTile}
    useBadges={useMyBadges}
    connect={{ Badge: StatusBadge, Note: StatusNote, BodyEnd: OwnerSetup, End: OwnerSwitch, hintKey, empty }}
    setupDoneTo="/admin"
  />,
)
```

`configure()` runs once before the first render: it sets the brand, starts i18next with the package's strings plus
the application's, and applies the saved appearance. A pre-paint script of the application (Family Hub:
`public/theme.js`) should apply the same theme and language rule before the bundle loads; it reads
`<prefix>.theme` and `<prefix>.lang`.

### `GatekeeperApp` props

| Prop | What it is | Default |
|---|---|---|
| `tabs` | The shell's tabs (`TabDef`: `id`, `root`, `icon`, `label` i18n key, `superadmin`). | `DEFAULT_TABS` (connect, account) |
| `routes` | The application's routes inside the signed-in shell. Give each a `handle: PageHandle` (`page`, `tab`, `depth`) for the tab highlight and the push/pop animation. | none |
| `publicRoutes` | The application's routes outside the shell (no session). | none |
| `resources` | The resources (MCP endpoints) of the account, from `GET /api/account`: `{id, name, description?, mcp_url, enabled}`. Used by connect and delete. | none |
| `ResourceTile` | A resource's icon (`{id, size: 'sm' \| 'md' \| 'lg', className}`); build it on `ResourceTile` with your own `icon` and `color`. | `ResourceTile` |
| `useBadges` | A hook `(me) => ({ [tabId]: true })`: red dots on tabs. | no dots |
| `connect` | Slots of each connect card, see below. | none |
| `setupDoneTo` | Where the first-run setup link lands. | `/connect` |

Connect card slots (`CardSlotProps` = `{ resource, owner }`; `resource` is the object `resources` returned):
`Badge` (right of the title), `Note` (under the description), `BodyEnd` (inside the card body after the
connections, shown only while the resource is enabled — start it with `<CardDivider />`), `End` (the card's end,
shown always), `hintKey(resource, owner)` (another i18n key for the footnote under the assistant buttons) and
`empty(me)` (`{ textKey?, action? }` for the empty page).

The routes the package owns: `/login`, `/setup`, `/join`, `/consent`, `/account/deleted` outside the shell;
`/connect`, `/account`, `/account/passkeys`, `/account/language`, `/account/appearance`, `/account/audit`,
`/account/delete` and a not-found page inside it. `gatekeeperRoutes({ routes, publicRoutes })` returns the route
table for an application that builds its own router; `AppProvider` gives the screens their slots without one.

### Building the application's own pages

Everything is exported from the package root: the design system (`Page`, `Section`, `Row`, `Button`, `Sheet`,
`ActionSheet`, `TextField`, `StatusPill`, `IconTile`, …), `useStepUp` (step-up around a dangerous call), `AdminOnly`,
`AuditPage` (`scope="admin"` for the superadmin's log), `FamiliesSection` (the superadmin's families), the API client
(`api`, `seg`, `ApiError`, `isApiError`), the queries (`qk`, `useMe`, `useAccount<T>()`, …), `errorText`, the
formatters, `toast`, `useLang`/`label`, and the wire types.

## Strings

`ru.json` and `en.json` in `ui/src/i18n` are flat key maps (no key separator; plurals `_one/_few/_many/_other` in
Russian, `_one/_other` in English). The application's strings override the package's key by key, so an application
can rename anything (`app.name`, the family wording, …). `packageStrings` exposes the package's own maps for an
application test that checks the merged copy.

## Developing the package

```sh
npm ci
npm run typecheck   # tsc -b
npm run lint        # eslint, 0 warnings
npm test            # vitest (jsdom)
```
