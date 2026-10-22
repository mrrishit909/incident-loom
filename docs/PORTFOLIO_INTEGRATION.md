# Portfolio integration

Three ways to show Incident Loom inside another site. All read the same public snapshot; none
needs a token.

## 1. Link (simplest)

Use `portfolio-manifest.json` for the card: name, description, live URL, preview image, tags,
capabilities and limitations. Deep links work: `#/runs/<run_id>/incidents/<incident_id>`, `#/detectors`, `#/timeline`,
`#/runs`, `#/request`, `#/about`.

## 2. Iframe

```html
<iframe src="https://mrrishit909.github.io/incident-loom/#/" title="Incident Loom investigation workspace"
        style="width:100%;height:80vh;border:0" loading="lazy"></iframe>
```

The app is fully self-contained; it opens in its dark theme, and a visitor's choice of Dark, Light or System is remembered in their browser.

## 3. Embedded component

The Pages site also serves an ES module build with React kept external:

- `https://mrrishit909.github.io/incident-loom/lib/incident-loom.js`
- `https://mrrishit909.github.io/incident-loom/lib/incident-loom.css`

```tsx
import "https://mrrishit909.github.io/incident-loom/lib/incident-loom.css";
import { IncidentLoomApp } from "incident-loom"; // or the URL above, with react/react-dom provided by the host

<IncidentLoomApp
  dataUrl="https://mrrishit909.github.io/incident-loom/data/"
  showShell={false}       // host supplies header and footer
  routing="memory"        // never reads or writes the host's URL
  theme="dark"            // "dark" (default) | "light" | "auto"
/>;
```

Or without React in the host page's own code: `mount(element, config)` returns an unmount
function.

| Config | Default | Meaning |
|---|---|---|
| `basePath` | build base | where the standalone site lives |
| `dataUrl` | `<basePath>data/` | snapshot directory (must allow CORS; GitHub Pages does) |
| `theme` | `dark` | colour theme (an embedded copy never reads or writes the visitor's stored choice) |
| `showShell` | `true` | render the app's own masthead and footer |
| `routing` | `hash` | `memory` for embedding |

Isolation: every CSS rule is scoped under `.il-root` and tokens are defined on that element, not
`:root`. Listeners (hashchange in hash mode, media queries, resize and intersection observers) are
registered in React effects and removed on unmount. Fonts are loaded only by the standalone site;
an embedded copy uses the host's fonts or the stylesheet's system sans and monospace fallbacks.
