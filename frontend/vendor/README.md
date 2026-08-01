# Vendored JavaScript

## three.module.js

- **Version**: three.js **0.169.0** (r169)
- **Upstream**: https://github.com/mrdoob/three.js — fetched from the
  official npm release artifact
  (`https://cdn.jsdelivr.net/npm/three@0.169.0/build/three.module.js`)
- **License**: MIT (see the header of the vendored file;
  Copyright 2010-2024 Three.js Authors)
- **SHA-256**: `0a3368c165eea773490aec7b77c22de70e3eac288503409256fdbf4d12578416`

Vendored so the site stays fully self-contained (no CDN at runtime).
Imported by `demo.js` via the relative path `./vendor/three.module.js`.
To upgrade: download the new pinned release artifact, replace the file,
and update this README (version + hash).
