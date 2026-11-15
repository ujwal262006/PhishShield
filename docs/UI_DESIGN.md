# PhishShield — UI Design System

PhishShield uses an original, sophisticated cybersecurity/SaaS aesthetic that
communicates security, trust, precision, clarity, and intelligence — without
"hacker" clichés (no matrix rain, skulls, or fake terminals).

## Design tokens

All visual values are centralized as CSS custom properties in
`app/static/css/style.css`. Theming is achieved by overriding tokens under
`[data-theme="light"]`; components never hardcode colors.

| Token group | Examples |
|-------------|----------|
| Surfaces | `--bg-primary`, `--bg-secondary`, `--surface`, `--surface-elevated`, `--border` |
| Text | `--text-primary`, `--text-secondary`, `--text-muted` |
| Brand | `--accent`, `--accent-strong`, `--brand-grad` |
| Semantic (risk) | `--success`, `--warning`, `--high`, `--danger` (+ soft variants) |
| Radius | `--radius-sm/md/lg/full` |
| Spacing | `--sp-1` … `--sp-8` |
| Shadows | `--shadow-sm/md/lg`, `--ring` |

## Theming

- Default theme is dark. Light mode is a deliberately designed palette, not an
  inversion.
- Preference is stored in `localStorage` (`phishshield-theme`) and falls back to
  the OS `prefers-color-scheme`.
- Toggle via the topbar/navbar button (`data-theme-toggle`) or Settings.
- `prefers-reduced-motion` disables transitions/animations.

## Components

Buttons (`.btn`, `.btn-primary/ghost/danger`, `.btn-sm/block`), cards (`.card`),
stat cards (`.stat`), badges (`.badge-SAFE|SUSPICIOUS|HIGH|CRITICAL`), severity
chips (`.sev-LOW|MEDIUM|HIGH`), forms, alerts, tables, pagination, pills/chips,
empty states (`.empty`), skeletons (`.skeleton`), spinner (`.spinner`).

Product-specific components:
- **Gauge** (`.gauge`) — circular risk score, driven by `--val` and `--gcolor`.
- **Meter** (`.meter`) — risk-breakdown bars.
- **Waterfall** (`.waterfall`) — point-by-point score contribution.
- **Forensics tree** (`.tree`, `.forensics`) — URL component breakdown.
- **Toasts** (`.toast-wrap`, `.toast`) — non-blocking notifications.
- **Modal** (`.modal-backdrop`, `.modal`) — confirmation dialogs.
- **Command palette** (`.cmdk`) — Ctrl/Cmd+K navigation.

## Layouts

- **`base.html`** — public/marketing layout with a sticky navbar (landing, auth,
  awareness, insights, methodology, integrity).
- **`shell.html`** — authenticated app shell: sidebar (Workspace / Learn / Account
  / Administration) + topbar (command palette, theme, user menu). Pages set
  `active_nav` to highlight the current item.
- Informational pages (`insights`, `methodology`, `awareness`, `integrity`) extend
  the shell when authenticated and the public base otherwise.

## JavaScript (`app/static/js/main.js`)

Dependency-free progressive enhancement exposing `window.PhishShield`:
`toggleTheme`, `setTheme`, `toast`, `confirm`. Handles theme, toasts (including
server flash messages via `[data-flash]`), sidebar toggle, user menu, expandable
indicators, confirmation modals (`form[data-confirm]`), the command palette
(`window.PHISHSHIELD_COMMANDS`), and the scanner loading state.

Charts use Chart.js from a CDN (allowed by the CSP) and read theme colors from
CSS variables so they adapt to dark/light mode.

## Accessibility

- Semantic landmarks (`nav`, `main`, `aside`, `header`, `footer`).
- Visible focus states via `:focus-visible` and `--ring`.
- Labels for all inputs; ARIA roles on menus/dialogs/command palette.
- Adequate contrast in both themes; `prefers-reduced-motion` respected.
- Keyboard navigation (command palette, focusable controls).

Full WCAG conformance would require manual testing with assistive technologies
and expert review; this document describes the measures implemented in code.

## Responsiveness

Fluid grids collapse at 1024/920/620px breakpoints. The sidebar becomes an
off-canvas drawer under 920px with a hamburger toggle and backdrop. Tables scroll
horizontally within `.table-wrap`. No horizontal page scroll at mobile widths.
