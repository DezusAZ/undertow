// Real-browser playback test. Loads Undertow in headless Chromium exactly as the user's
// browser would, logs in, opens a library title, clicks Play, and reports whether the
// <video> element actually advances past 0s — the thing curl can never verify.
const { chromium } = require('playwright-core');

const BASE = process.env.BASE || 'http://127.0.0.1:8722';
const PW = process.env.VT_PASSWORD || '';

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROME_PATH,
    args: ['--no-sandbox', '--autoplay-policy=no-user-gesture-required'],
  });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();

  const netFails = [];
  page.on('response', (r) => {
    if (r.status() >= 400 && /\/(hls|playfile|stream|prep)/.test(r.url()))
      netFails.push(r.status() + ' ' + r.url().replace(BASE, ''));
  });
  const consoleErrs = [];
  page.on('console', (m) => { if (m.type() === 'error') consoleErrs.push(m.text().slice(0, 160)); });

  const log = (...a) => console.log('  ' + a.join(' '));
  try {
    // --- log in ---
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.fill('input[name=pw]', PW);
    await Promise.all([
      page.waitForNavigation({ timeout: 20000 }).catch(() => {}),
      page.click('button[type=submit], input[type=submit], button'),
    ]);
    log('logged in, url =', page.url());

    // --- go to the Library tab ---
    await page.goto(BASE + '/#library', { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(4000);

    // Library shows poster TILES; Play lives inside the detail modal you open by
    // clicking a tile. Open the tile for the file we want, then click Play.
    const want = (process.env.WANT || 'Rob').toLowerCase();
    await page.waitForSelector('.lib-tile', { timeout: 20000 });
    const tiles = page.locator('.lib-tile');
    const nTiles = await tiles.count();
    log('library tiles:', nTiles);
    let opened = false;
    for (let i = 0; i < nTiles; i++) {
      const t = tiles.nth(i);
      const txt = ((await t.innerText().catch(() => '')) || '').toLowerCase();
      if (txt.includes(want)) { await t.click(); opened = true; break; }
    }
    if (!opened) { await tiles.first().click(); }
    log('opened a title; waiting for the Play button…');
    const playBtn = page.locator('button:has-text("Play")').first();
    await playBtn.waitFor({ timeout: 20000 });
    log('clicking Play…');
    await playBtn.click();

    // --- wait for a <video> to appear and actually play ---
    await page.waitForSelector('video', { timeout: 30000 });
    log('video element mounted; waiting for playback to advance…');

    let result = null;
    const started = Date.now();
    while (Date.now() - started < 90000) {
      result = await page.evaluate(() => {
        const v = document.querySelector('video');
        if (!v) return { state: 'no-video' };
        return {
          state: 'ok',
          currentTime: +v.currentTime.toFixed(2),
          duration: isFinite(v.duration) ? +v.duration.toFixed(1) : null,
          readyState: v.readyState,           // 4 = HAVE_ENOUGH_DATA
          videoWidth: v.videoWidth,
          videoHeight: v.videoHeight,
          error: v.error ? v.error.code : null,
          paused: v.paused,
        };
      });
      if (result.error) { log('VIDEO ERROR code', result.error); break; }
      if (result.currentTime > 1.5 && result.videoWidth > 0) break;   // real playback
      await page.waitForTimeout(1500);
    }

    log('final video state:', JSON.stringify(result));
    const playing = result && result.currentTime > 1.5 && result.videoWidth > 0 && !result.error;
    log('NET FAILURES:', netFails.length ? netFails.slice(0, 6).join(' ; ') : 'none');
    if (consoleErrs.length) log('CONSOLE ERRORS:', consoleErrs.slice(0, 4).join(' || '));
    log('RESULT:', playing
      ? `PLAYS — advanced to ${result.currentTime}s at ${result.videoWidth}x${result.videoHeight}`
      : 'DID NOT PLAY');
    process.exitCode = playing ? 0 : 1;
  } catch (e) {
    log('TEST ERROR:', e.message.slice(0, 200));
    log('recent net failures:', netFails.slice(0, 6).join(' ; ') || 'none');
    process.exitCode = 2;
  } finally {
    await browser.close();
  }
})();
