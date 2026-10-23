# Motion explainer

`scene.html` is the animation (SVG + CSS keyframes on one 26 s timeline). `render.mjs` scrubs every
animation to exact frame times in headless Chrome and encodes `agent-sandbox.mp4` (H.264, 1200×600, 30 fps)
and `agent-sandbox.gif` (960 px, 12 fps) with ffmpeg:

```sh
npm i puppeteer-core          # once, next to render.mjs or anywhere on NODE_PATH
CHROME=/path/to/chrome node docs/motion/render.mjs docs/motion
```

Edit the text or timings in `scene.html`, re-render, commit both outputs. The README embeds the GIF because
GitHub plays only videos uploaded through its web UI; to get the native player, drag the MP4 into the README
editor on GitHub and replace the image line with the URL it produces.
