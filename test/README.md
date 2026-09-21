# Browser playback test

Loads Undertow in a **real headless Chromium**, logs in, opens a Library title, clicks
Play, and asserts the `<video>` element actually advances past 0s at a real resolution.

This exists because playback bugs kept passing endpoint-level tests and then failing in
an actual browser (e.g. an HLS playlist whose relative segment URIs a browser resolves
differently than a direct curl). curl proves the server answers; only a browser proves
the *player* works.

## Run it

Needs Node and a Chromium with GUI libraries. On a minimal host (e.g. ZimaOS) run it
inside a container that already has those libraries — the linuxserver webtop image works
and needs no apt:

    CHROME=/path/to/playwright/chromium/chrome-linux64/chrome    # or any chrome/chromium
    docker run --rm --network host -v /DATA:/DATA -v "$PWD/test":/work \
      -e CHROME_PATH="$CHROME" -e BASE=http://127.0.0.1:8722 \
      -e VT_PASSWORD='yourpassword' -e WANT=Rob -e HOME=/tmp \
      --entrypoint /path/to/node \
      lscr.io/linuxserver/webtop:debian-xfce /work/browser-playback-test.js

Env: BASE, VT_PASSWORD, WANT (substring of the title to open), CHROME_PATH.
Exit 0 = the video played. Requires `npm i playwright-core` where node can find it
(on this box: `/DATA/projects/toolchains/playwright-node/node_modules`, pass it as `NODE_PATH`).

## Deep Hunt test (`browser-hunt-test.js`)

Same harness, different journey: logs in, starts a hunt for an easy legal target (default
"Big Buck Bunny 1080p"), and asserts what the user sees — the card, an honest brain banner,
the target profile getting built, the activity log filling in, results with an AI verdict
badge and a Download button, per-source yield chips, Stop → stopped, Delete → gone, and that
an expired session redirects to /login instead of freezing the tab. Cleans up its hunt.

    docker run --rm --network host -v /DATA:/DATA -v "$PWD/test":/work \
      -e CHROME_PATH="$CHROME" -e BASE=http://127.0.0.1:8722 -e VT_PASSWORD='yourpassword' \
      -e NODE_PATH=/DATA/projects/toolchains/playwright-node/node_modules -e HOME=/tmp \
      --entrypoint /DATA/.local/bin/node lscr.io/linuxserver/webtop:debian-xfce /work/browser-hunt-test.js

Env: GOAL, DESC, WAIT_RESULTS_MS (default 7 min — the hunt is a background agent; the AI
profile alone takes ~30 s). Exit 0 = every check passed.
