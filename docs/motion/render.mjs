// Renders docs/motion/scene.html to MP4 and GIF.
//   npm i puppeteer-core   (next to this file or on NODE_PATH); needs Chrome and ffmpeg.
//   CHROME=/path/to/chrome node docs/motion/render.mjs [outDir]
// The scene exposes window.seek(ms): every frame is rendered at an exact time, so the
// result is deterministic and independent of machine speed.
import puppeteer from 'puppeteer-core';
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(process.argv[2] || here);
const scene = process.env.SCENE || resolve(here, 'scene.html');
const frames = resolve(out, 'frames');
const fps = 30;
const chrome = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

rmSync(frames, { recursive: true, force: true });
mkdirSync(frames, { recursive: true });
const browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ['--hide-scrollbars', '--force-device-scale-factor=1'] });
const page = await browser.newPage();
await page.setViewport({ width: 1920, height: 1080, deviceScaleFactor: 1 });
await page.goto('file://' + scene);
const durationMs = await page.evaluate(() => window.DURATION_MS);
const total = Math.round((durationMs / 1000) * fps);
for (let i = 0; i < total; i++) {
  await page.evaluate(ms => window.seek(ms), (i / fps) * 1000);
  await page.screenshot({ path: `${frames}/f${String(i).padStart(5, '0')}.png` });
  if (i % 150 === 0) process.stdout.write(`frame ${i}/${total}\n`);
}
await browser.close();
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-framerate', String(fps), '-i', `${frames}/f%05d.png`, '-c:v', 'libx264', '-preset', 'slow', '-pix_fmt', 'yuv420p', '-crf', '20', '-movflags', '+faststart', resolve(out, 'agent-sandbox.mp4')]);
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', resolve(out, 'agent-sandbox.mp4'), '-vf', 'fps=10,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=96:stats_mode=diff[p];[s1][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle', '-loop', '0', resolve(out, 'agent-sandbox.gif')]);
rmSync(frames, { recursive: true, force: true });
console.log('done:', resolve(out, 'agent-sandbox.mp4'), resolve(out, 'agent-sandbox.gif'));
