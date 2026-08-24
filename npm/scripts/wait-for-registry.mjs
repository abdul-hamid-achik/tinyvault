#!/usr/bin/env node
// Poll registry.npmjs.org until every TinyVault npm package serves <version>.
//
// `npm install` after a just-finished publish can fail with ETARGET even
// though the publish job succeeded: the registry CDN lags, and npm's local
// cache then remembers the miss so retries of `npm install` keep failing.
// This script talks to the registry over HTTP (no npm cache) and only exits
// 0 when the version document for the main package and every platform
// package is 200.
//
// Usage: node npm/scripts/wait-for-registry.mjs <version>
// Env: NPM_WAIT_MS (default 300000), NPM_WAIT_INTERVAL_MS (default 15000)

const version = (process.argv[2] ?? "").replace(/^v/, "");
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(
    `usage: node npm/scripts/wait-for-registry.mjs <version>; got ${JSON.stringify(process.argv[2])}`,
  );
  process.exit(2);
}

const pkgs = [
  "@thelacanians/tinyvault",
  "@thelacanians/tinyvault-darwin-arm64",
  "@thelacanians/tinyvault-darwin-x64",
  "@thelacanians/tinyvault-linux-arm64",
  "@thelacanians/tinyvault-linux-x64",
  "@thelacanians/tinyvault-win32-arm64",
  "@thelacanians/tinyvault-win32-x64",
];

const timeoutMs = Number(process.env.NPM_WAIT_MS ?? 5 * 60 * 1000);
const intervalMs = Number(process.env.NPM_WAIT_INTERVAL_MS ?? 15_000);

function encodeName(name) {
  return name.replaceAll("/", "%2f");
}

async function hasVersion(pkg) {
  const url = `https://registry.npmjs.org/${encodeName(pkg)}/${version}`;
  try {
    const res = await fetch(url, { cache: "no-store" });
    return res.ok;
  } catch {
    return false;
  }
}

const start = Date.now();
for (;;) {
  const results = await Promise.all(
    pkgs.map(async (pkg) => [pkg, await hasVersion(pkg)]),
  );
  const missing = results.filter(([, ok]) => !ok).map(([pkg]) => pkg);
  if (missing.length === 0) {
    console.log(`registry has all ${pkgs.length} packages at ${version}`);
    process.exit(0);
  }
  const elapsed = Date.now() - start;
  if (elapsed >= timeoutMs) {
    console.error(
      `timed out after ${Math.round(elapsed / 1000)}s waiting for npm to serve ${version}: still missing ${missing.join(", ")}`,
    );
    process.exit(1);
  }
  console.log(
    `still missing ${missing.length}/${pkgs.length} at ${version}: ${missing.join(", ")}`,
  );
  await new Promise((resolve) => setTimeout(resolve, intervalMs));
}
