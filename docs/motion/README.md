# Motion explainer

`scene.html` is the animation: an SVG stage plus a small JavaScript timeline (`show`, `along`, `type`,
`light` calls at absolute seconds; `window.seek(ms)` renders any instant). `render.mjs` drives `seek` frame
by frame in headless Chrome and encodes `agent-sandbox.mp4` (H.264, 1920×1080, 30 fps) and
`agent-sandbox.gif` (960 px, 10 fps) with ffmpeg:

```sh
npm i puppeteer-core          # once, next to render.mjs or anywhere on NODE_PATH
CHROME=/path/to/chrome node docs/motion/render.mjs docs/motion
```

Edit the text or timings in `scene.html` (open it in a browser to preview live), re-render, commit both outputs.
Font sizes on `<text>` must be inline styles: a CSS class on `text` would override presentation attributes. The README embeds the GIF because
GitHub plays only videos uploaded through its web UI; to get the native player, drag the MP4 into the README
editor on GitHub and replace the image line with the URL it produces.
