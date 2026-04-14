# Branding drop-folder

The app renders optional watermark backdrops using whatever files you
drop into this folder. Nothing here is shipped with the repo — you
supply your own licensed copies.

## File names the app looks for

| File                  | Usage                                                      |
| --------------------- | ---------------------------------------------------------- |
| `logo.svg`            | Top-left wordmark + subtle repeating watermark             |
| `logo.png`            | Fallback if `logo.svg` is absent                           |
| `portrait.jpg`        | Hero-area right-side backdrop (faded, behind the `<h1>`)    |
| `portrait.png`        | Fallback if `portrait.jpg` is absent                        |
| `favicon.ico`         | Browser tab icon                                            |

**Size guidance:**
- `logo.svg` — any size (rendered at ~56px tall in the header, ~180px in the watermark)
- `portrait.jpg` — ~1200×800 recommended, JPG quality ≥ 85, faded to 15% opacity in the hero

## Why a drop-folder instead of bundled images?

- **Licensing.** Zscaler marks and executive photos are trademarked / publicity-rights protected. Your organization has a license to display them internally; this public repo does not.
- **Security.** Images loaded through this folder are served from the same origin as the app, never from a third-party CDN — no cross-origin pixel tracking possible.
- **Swappability.** You can replace these files with your own branding (partner co-brand, customer deployment, internal branding) without touching code.

## Security notes

- Files are served read-only via FastAPI's `StaticFiles` mount at `/static/branding/`.
- The app's Content-Security-Policy header (`img-src 'self' data:`) blocks any attempt to load images from elsewhere, so swapping the files is the only way to change the visual.
- `SVG` files are rendered in CSS `background-image` only — not inlined into the DOM — so even a malicious SVG can't execute script against the page.
- The app does not read any metadata (EXIF / XMP) from dropped files — only their bytes are served.

## How to remove the branding

Delete the files. The app falls back to a clean Zscaler-blue gradient with no portrait.
