# design/fonts/

Embedded brand type for the self-contained (air-gapped) product surfaces.

## fraunces-latin-var.woff2
The brand display serif, **Fraunces** — the Latin unicode-range slice of the
variable font (axes: `opsz`, `wght`; weights 300–500, the range the receipt and
certificate use). Google Fonts pre-subsets by unicode-range, so this is already
a tight slice (~67 KB); no local subsetting step is involved.

It is embedded as base64 into two templates at render time so they render with
the brand serif fully offline, no CDN:
- `packages/core/src/session/preview_template.html` (via `render_preview_html`)
- `packages/cli/src/commands/certificate_template.html` (via `agent.rs`)

Both `include_bytes!` this file and substitute the `data:` URI into the
template's `@font-face`. Body and mono stay on the system stack (system-ui /
ui-monospace) to keep weight down; the serif is the one high-impact brand face.

**License:** SIL Open Font License 1.1 — see `Fraunces-OFL.txt`, which must
travel with the font. Free to embed and redistribute.

To refresh: fetch the Latin slice from the Google Fonts `css2` API for
`Fraunces:opsz,wght@9..144,300..500` with a modern browser UA (it returns a
woff2 URL per unicode-range) and replace this file.
