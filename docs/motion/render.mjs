// Renders docs/motion/scene.html to MP4 and GIF.
//   node docs/motion/render.mjs [outDir]   (needs: Chrome, ffmpeg, `npm i puppeteer-core` next to the script or NODE_PATH)
// Frames are produced by scrubbing every CSS animation to an exact time, so the result is
// deterministic and independent of machine speed.
import puppeteer from 'puppeteer-core';
import { execFileSync } from 'node:child_process';
import { mkdirSync, rmSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(process.argv[2] || here);
const frames = resolve(out, 'frames');
const fps = 30, seconds = 26;
const chrome = process.env.CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

rmSync(frames, { recursive: true, force: true });
mkdirSync(frames, { recursive: true });
const browser = await puppeteer.launch({ executablePath: chrome, headless: true, args: ['--hide-scrollbars'] });
const page = await browser.newPage();
await page.setViewport({ width: 1200, height: 600, deviceScaleFactor: 1 });
await page.goto('file://' + resolve(here, 'scene.html'));
await page.evaluate(() => document.getAnimations().forEach(a => a.pause()));
const total = fps * seconds;
for (let i = 0; i < total; i++) {
  const t = (i / fps) * 1000;
  await page.evaluate(ms => {
    for (const a of document.getAnimations()) {
      const tl = a.effect.getTiming();
      const dur = typeof tl.duration === 'number' ? tl.duration : 0;
      const delay = tl.delay || 0;
      a.currentTime = tl.iterations === Infinity && dur > 0 ? delay + ((ms - delay) % dur + dur) % dur : ms;
    }
  }, t);
  await page.screenshot({ path: `${frames}/f${String(i).padStart(5, '0')}.png` });
  if (i % 60 === 0) process.stdout.write(`frame ${i}/${total}\n`);
}
await browser.close();
execFileSync('ffmpeg', ['-y', '-framerate', String(fps), '-i', `${frames}/f%05d.png`, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '20', '-movflags', '+faststart', resolve(out, 'agent-sandbox.mp4')], { stdio: 'inherit' });
execFileSync('ffmpeg', ['-y', '-i', resolve(out, 'agent-sandbox.mp4'), '-vf', 'fps=12,scale=960:-1:flags=lanczos,split[s0][s1];[s0]palettegen=max_colors=128[p];[s1][p]paletteuse=dither=bayer:bayer_scale=5', '-loop', '0', resolve(out, 'agent-sandbox.gif')], { stdio: 'inherit' });
rmSync(frames, { recursive: true, force: true });
console.log('done:', resolve(out, 'agent-sandbox.mp4'), resolve(out, 'agent-sandbox.gif'));
