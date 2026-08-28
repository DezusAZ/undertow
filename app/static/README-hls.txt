hls.min.js — hls.js v1.5.17 (Apache-2.0), vendored deliberately.

Chrome, Edge and Firefox cannot play HLS natively; only Safari can. Serving the player
library ourselves (rather than from a CDN) keeps Undertow working offline and means a
third party never sees which box is streaming what — the whole point of this tool.

Source: https://cdn.jsdelivr.net/npm/hls.js@1.5.17/dist/hls.min.js
sha256:  484054e8cd03d3f6d1781fb7f402bdc318d8a4c527f933a95c624e27cc9a9470
(sourceMappingURL comment stripped; the .map is not shipped.)
