// Real-browser Deep Hunt test. Logs in, starts a hunt for an easy legal target, and
// asserts what a user would see: the card appears, the brain banner is honest, the target
// profile gets built, the "doing now" line and activity log fill in, real results with a
// verdict badge show up, Stop stops it, Delete removes it, and a logged-out tab goes to
// /login instead of silently freezing. Exit 0 = all of it happened.
const { chromium } = require('playwright-core');

const BASE = process.env.BASE || 'http://127.0.0.1:8722';
const PW = process.env.VT_PASSWORD || '';
const GOAL = process.env.GOAL || 'Big Buck Bunny 1080p';
const DESC = process.env.DESC || 'the 2008 Blender open movie, 1080p or better, any container';
const WAIT_RESULTS_MS = +(process.env.WAIT_RESULTS_MS || 420000);

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROME_PATH, args: ['--no-sandbox'] });
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const errs = [];
  page.on('console', (m) => { if (m.type() === 'error') errs.push(m.text().slice(0, 160)); });
  page.on('pageerror', (e) => errs.push('pageerror: ' + String(e).slice(0, 160)));
  page.on('dialog', (d) => d.accept());
  const log = (...a) => console.log('  ' + a.join(' '));
  const fails = [];
  const check = (ok, what) => { log((ok ? 'PASS ' : 'FAIL ') + what); if (!ok) fails.push(what); };
  let hid = null;
  try {
    await page.goto(BASE + '/login', { waitUntil: 'domcontentloaded', timeout: 20000 });
    await page.fill('input[name=pw]', PW);
    await Promise.all([page.waitForNavigation({ timeout: 20000 }).catch(() => {}), page.click('button[type=submit], input[type=submit], button')]);
    log('logged in:', page.url());

    await page.goto(BASE + '/#hunt', { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#hgoal', { timeout: 20000 });
    await page.waitForTimeout(2500);
    const banner = (await page.locator('#huntbrain').innerText().catch(() => '')) || '';
    log('brain banner:', banner.slice(0, 120).replace(/\s+/g, ' '));
    check(/active|basic mode|off|does not answer|GPU|paused|failed/i.test(banner), 'brain banner renders a state');

    // in-app guide: open for a newcomer with no hunts, examples fill the form, toggle hides it
    const noHunts = (await page.locator('.hunt').count()) === 0;
    const guideOpen = await page.evaluate(() => { const g = document.getElementById('hunthelp'); return !!g && !g.hidden; });
    check(!noHunts || guideOpen, 'guide panel is open for a first-time user (no hunts yet)');
    if (!guideOpen) await page.click('#hhelpbtn');
    await page.waitForSelector('.hexample', { timeout: 5000 });
    await page.locator('.hexample').first().click();
    const filled = await page.evaluate(() => ({ g: document.getElementById('hgoal').value, d: document.getElementById('hdesc').value, c: document.getElementById('hcat').value }));
    check(filled.g.length > 5 && filled.d.length > 10 && filled.c !== 'all', 'clicking an example fills target, category and description');
    await page.click('#hhelpbtn');
    check(await page.evaluate(() => document.getElementById('hunthelp').hidden), 'guide toggle hides the panel');
    const hints = await page.evaluate(() => ['#hgoal', '#hcat', '#hpace', '#hdesc', '#hgo', '.tabbtn[data-tab=hunt]'].filter(s => { const e = document.querySelector(s); return e && e.title && e.title.length > 20; }).length);
    check(hints === 6, 'hover hints present on the hunt form and tab (' + hints + '/6)');

    // start a hunt
    await page.fill('#hgoal', GOAL);
    await page.selectOption('#hcat', 'movies').catch(() => {});
    await page.selectOption('#hpace', 'aggressive').catch(() => {});
    await page.fill('#hdesc', DESC);
    await page.press('#hdesc', 'Enter');                       // description sits inside the form now
    await page.waitForSelector('.hunt', { timeout: 20000 });
    hid = await page.evaluate(() => { const d = document.querySelector('.huntdot'); return d ? d.id.replace('hdot-', '') : null; });
    check(!!hid, 'hunt card appeared (id ' + hid + ')');
    const err = (await page.locator('#hunterr').innerText().catch(() => '')) || '';
    check(!err.trim(), 'no create error shown' + (err ? ' [' + err + ']' : ''));

    // profile + activity
    let prof = '';
    const t0 = Date.now();
    while (Date.now() - t0 < 150000) {
      prof = (await page.locator('#hprof-' + hid).innerText().catch(() => '')) || '';
      if (/target/i.test(prof) && !/building/i.test(prof)) break;
      await page.waitForTimeout(3000);
    }
    log('profile line:', prof.slice(0, 160).replace(/\s+/g, ' '));
    check(/target/i.test(prof) && !/building/i.test(prof), 'target profile built and shown (' + Math.round((Date.now() - t0) / 1000) + 's)');

    await page.click('#hltog-' + hid);
    await page.waitForTimeout(6000);
    const logTxt = (await page.locator('#hlog-' + hid).innerText().catch(() => '')) || '';
    log('activity log:', logTxt.slice(0, 200).replace(/\s+/g, ' '));
    check(/profiled|planned|→|kept/i.test(logTxt), 'activity log has entries');
    const now = (await page.locator('#hrecent-' + hid).innerText().catch(() => '')) || '';
    log('doing now:', now.slice(0, 160).replace(/\s+/g, ' '));

    // results (with a verdict badge + download button)
    await page.click('#htog-' + hid);
    let nres = 0, badge = 0, dl = 0;
    const t1 = Date.now();
    while (Date.now() - t1 < WAIT_RESULTS_MS) {
      nres = await page.locator('#hres-' + hid + ' .t').count();
      if (nres > 0) {
        badge = await page.locator('#hres-' + hid + ' .vbadge').count();
        dl = await page.locator('#hres-' + hid + ' button:has-text("Download")').count();
        break;
      }
      await page.waitForTimeout(5000);
    }
    log('results:', nres, 'badges:', badge, 'download buttons:', dl, '(' + Math.round((Date.now() - t1) / 1000) + 's)');
    check(nres > 0, 'results rendered');
    check(badge > 0, 'AI verdict badge shown on results');
    check(dl > 0, 'download button present');
    const yields = (await page.locator('#hyield-' + hid).innerText().catch(() => '')) || '';
    check(/→/.test(yields), 'per-source yield chips shown (' + yields.replace(/\s+/g, ' ').slice(0, 80) + ')');

    // stop / delete
    await page.click('.hunt button:has-text("Stop")');
    await page.waitForTimeout(5000);
    const st = (await page.locator('#hstatus-' + hid).innerText().catch(() => '')) || '';
    check(/stopped/i.test(st), 'Stop → status stopped (' + st.trim() + ')');
    await page.click('.hunt button:has-text("Delete")');
    await page.waitForTimeout(5000);
    const gone = (await page.locator('#hdot-' + hid).count()) === 0;
    check(gone, 'Delete removed the card');
    hid = gone ? null : hid;

    // logged-out behaviour: clear cookies, poll should redirect to /login, not freeze
    await ctx.clearCookies();
    await page.waitForTimeout(6000);
    check(/\/login/.test(page.url()), 'expired session redirects to /login (url ' + page.url() + ')');
  } catch (e) {
    fails.push('exception: ' + String(e).slice(0, 200));
    log('EXCEPTION', String(e).slice(0, 200));
  } finally {
    if (hid) { try { await page.request.post(BASE + '/hunt/delete', { data: { id: hid } }); } catch (_) {} }
    await browser.close();
  }
  if (errs.length) log('console errors:', errs.slice(0, 5).join(' | '));
  console.log(fails.length ? 'RESULT: FAIL ' + fails.length + ' (' + fails.join('; ') + ')' : 'RESULT: PASS');
  process.exit(fails.length ? 1 : 0);
})();
