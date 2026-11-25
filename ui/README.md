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

`configure()` runs once before the first render: it sets the brand and the people options, starts i18next with the
package's strings plus the application's, and applies the saved appearance. The options below default to Family
Hub's behaviour; the first two mirror `people.Options` of the Go side:

| Option | What it does | Default |
|---|---|---|
| `singleAccount: true` | `people.Options.SingleAccount`: `FamiliesSection` renders nothing and fetches nothing. | `false` |
| `coOwners: true` | `people.Options.CoOwners`: the superadmin's invite sheet offers a role, «Участник» or «Совладелец»; a co-owner's invite (`role: "owner"`) has no access pickers. | `false` |
| `accountDelete: false` | Hides the owner's «Удалить всё»: its section on `/account` goes, and `/account/delete` is the not-found page. | `true` |

A pre-paint script of the application (Family Hub: `public/theme.js`) should apply the same theme and language rule
before the bundle loads; it reads `<prefix>.theme` and `<prefix>.lang`.

### `GatekeeperApp` props

| Prop | What it is | Default |
|---|---|---|
| `tabs` | The shell's tabs (`TabDef`: `id`, `root`, `icon`, `label` i18n key; who sees it: `superadmin`, `owner` (owners only), `visible(me)` (the application's rule), checked in that order by `tabVisible`). | `DEFAULT_TABS` (connect, account) |
| `routes` | The application's routes inside the signed-in shell. Give each a `handle: PageHandle` (`page`, `tab`, `depth`) for the tab highlight and the push/pop animation. | none |
| `publicRoutes` | The application's routes outside the shell (no session). | none |
| `indexRoute` | The application's page at `/` inside the shell (a react-router index route without `index`: `{ element \| Component \| lazy, handle }`). It is the shell's index route, so the order of `routes` and `publicRoutes` does not matter. | a redirect to `/connect` |
| `resources` | The resources (MCP endpoints) of the account, from `GET /api/account`: `{id, name, description?, mcp_url, enabled}`. Used by connect and delete. | none |
| `ResourceTile` | A resource's icon (`{id, size: 'sm' \| 'md' \| 'lg', className}`); build it on `ResourceTile` with your own `icon` and `color`. | `ResourceTile` |
| `useBadges` | A hook `(me) => ({ [tabId]: true })`: red dots on tabs. | no dots |
| `connect` | Slots of each connect card, see below. | none |
| `setupDoneTo` | Where the first-run setup link lands. | `/connect` |
| `usePermissions` | The application's permission catalog (`people.Options.Permissions`), see below. | none: no access pickers |
| `useInvitesDisabled` | A hook called on the people list. A returned text turns invites off and stands in place of the invite button, greyed (Homie: invites are off in quick mode). | invites on |
| `Overlay` | A layer of the application over every signed-in page (`{ me }`): the shell mounts it once, after the tab bar and outside the page transitions, so it survives navigation and can use `useStepUp`. It positions itself: `position: fixed` with `z-index` above 30 (the tab bar's and the sidebar's), and on phones `bottom: calc(var(--tab-h) + env(safe-area-inset-bottom))` to sit above the tab bar (`lg:` the sidebar is on the left, so `bottom: 0`). | none |
| `live` | `'sse'` or `'poll'`: how the application's own data hooks follow changes, read with `useLiveMode()`. The only prop that may change after the first render (e.g. `'poll'` behind a Cloudflare quick tunnel, which carries no SSE). The package's own screens do not use it. | `'sse'` |

Connect card slots (`CardSlotProps` = `{ resource, owner }`; `resource` is the object `resources` returned):
`Badge` (right of the title), `Note` (under the description), `BodyEnd` (inside the card body after the
connections, shown only while the resource is enabled — start it with `<CardDivider />`), `End` (the card's end,
shown always), `hintKey(resource, owner)` (another i18n key for the footnote under the assistant buttons) and
`empty(me)` (`{ textKey?, action? }` for the empty page).

The routes the package owns: `/login`, `/setup`, `/join`, `/consent`, `/account/deleted` outside the shell;
`/connect`, `/account`, `/account/passkeys`, `/account/language`, `/account/appearance`, `/account/audit`,
`/account/delete` and a not-found page inside it. `gatekeeperRoutes({ routes, publicRoutes, indexRoute })` returns the route
table for an application that builds its own router; `AppProvider` gives the screens their slots without one.

### People's access: the permission catalog and terms

`usePermissions` is a hook the screens call wherever they need the catalog. It returns `PermissionInfo[]`
(`{id, title, group?}`, the JSON of `core.PermissionInfo`; `title` and `group` may also be label maps
`{"ru": …, "en": …}`), or `undefined` while it loads. The package does not fetch it itself, so the application picks
the source. Two ways work:

```tsx
// from GET /api/account, where the application adds it with people.AccountFields (one request, refreshed with the account)
const useCatalog = () => useAccount<MyAccount>().data?.permission_catalog
// or from an endpoint of the application
const useCatalog = () => useQuery({ queryKey: ['permissions'], queryFn: () => api.get<PermissionInfo[]>('/home/permissions') }).data

<GatekeeperApp usePermissions={useCatalog} … />
```

With the prop set:
- **The invite sheet** asks what the person may use (`access.what`: «Всё», which sends `["all"]` and covers what is
  added later, or ticks from the catalog, grouped) and for how long (`access.term`: «Навсегда», «1 день», «3 дня»,
  «Неделя», «Месяц», «До даты…»). A term ends at 23:59:59 of its last day in the browser's time zone. "1 day" ends
  tomorrow, "a month" ends on the same day next month, and the last day can be at most 364 days ahead, so the end
  stays within the server's one-year limit. The sheet sends `POST /api/account/invites {name, permissions,
  access_until?}`; «Навсегда» leaves `access_until` out.
- **The people list** shows a term («до 3 декабря»). A person whose term is over (`active: false`, or
  `access_until` in the past) is greyed, with a «Продлить» button.
- **A tap on a person** opens the member detail (`MemberSheet`): what they may use, the term, their assistant
  connections (each one can be cut), «Изменить доступ», «Закрыть доступ сейчас» and «Удалить».
  - Changes go out as `PATCH /api/account/members/{id}` and carry only the fields that were touched.
  - The server asks for step-up when a change widens access. The call runs through `useStepUp`, so the passkey sheet
    appears and the same `PATCH` is retried once.
  - «Закрыть доступ сейчас» sends `access_until` set to the current time.
  - «Продлить» opens the editor with «Неделя» picked.
  - With `coOwners`, another owner is changed or removed only by the superadmin.

Without the prop (Family Hub), none of this appears and every screen sends what it did before.

The wording is generic. An application names its own things by overriding the `access.*` keys, e.g.
`"access.what": "Устройства"`, `"access.all": "Все устройства"`. `PermissionPicker` and `TermPicker` are exported
for the application's own screens, along with the helpers in `lib/access` (`termEnd`, `PERMISSION_ALL`, …).

### Sign-in and join with these options

- **A co-owner's invite.** `POST /api/auth/token` answers `co_owner: true` for it. The join page then says «Вас
  зовут в «…» совладельцем», skips the account-name step and sends no `account_name`. The first owner's invite
  (`kind: "owner"` without `co_owner`) looks as before.
- **An ended term.** Sign-in answers 403 `access_ended`. The panel shows `login.ended` («Ваш доступ закончился.
  Попросите владельца продлить его.»). Every other refusal keeps `login.failed`, a plain 403 `forbidden` included.
  Anywhere else, `errorText` words the code as `error.access_ended`.

### Errors

- **`ApiError`** carries `status`, `code` (the body's `error`) and `message`. `details` holds every other key of
  the error body (`fields`, `callId`, `jobId`, …): an empty object when there are none.
- **`errorText(err, t)`** words an error by its code (`error.<code>`), or with the generic text when there is no such
  key. An application adds words for its own codes in its strings (e.g. `"error.misdirected"`).
- **The shell's error screen.** When `GET /api/me` fails with anything but `no_session` or "offline", the shell's
  screen shows these words under «Не получилось», with «Повторить».

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
