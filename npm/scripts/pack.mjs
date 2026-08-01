#!/usr/bin/env node
// pack.mjs — assembles the @thelacanians/tinyvault npm packages from GitHub
// release assets.
//
// GoReleaser publishes raw, versionless binaries plus checksums.txt to each
// GitHub release (see .goreleaser.yml). This script:
//   1. downloads the six platform binaries for <version>;
//   2. verifies each against checksums.txt (sha256);
//   3. drops them into npm/platforms/<pkg>/bin/;
//   4. rewrites the version into every package.json (platforms + main) and
//      pins the main package's optionalDependencies to that version.
//
// Usage: node npm/scripts/pack.mjs <version>   (no leading "v")
// Requires Node >= 18 (global fetch). Run in CI (npm-publish.yml), not on a
// laptop: it downloads ~170 MB from GitHub.

import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = "abdul-hamid-achik/tinyvault";
const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// npm platform key -> GoReleaser asset name. Go uses "windows"/"amd64" where
// npm uses "win32"/"x64", and GoReleaser appends .exe for Windows binaries.
const PLATFORMS = [
  { pkg: "darwin-arm64", asset: "tvault-darwin-arm64", exe: false },
  { pkg: "darwin-x64", asset: "tvault-darwin-amd64", exe: false },
  { pkg: "linux-arm64", asset: "tvault-linux-arm64", exe: false },
  { pkg: "linux-x64", asset: "tvault-linux-amd64", exe: false },
  { pkg: "win32-arm64", asset: "tvault-windows-arm64.exe", exe: true },
  { pkg: "win32-x64", asset: "tvault-windows-amd64.exe", exe: true },
];

const version = (process.argv[2] ?? "").replace(/^v/, "");
if (!/^\d+\.\d+\.\d+$/.test(version)) {
  console.error(
    `usage: node npm/scripts/pack.mjs <version> (e.g. 0.17.1); got ${JSON.stringify(process.argv[2])}`,
  );
  process.exit(2);
}

const base = `https://github.com/${repo}/releases/download/v${version}`;

async function download(name) {
  const res = await fetch(`${base}/${name}`);
  if (!res.ok) {
    throw new Error(`GET ${name}: HTTP ${res.status} (does release v${version} exist?)`);
  }
  return Buffer.from(await res.arrayBuffer());
}

async function main() {
  const checksums = (await download("checksums.txt")).toString("utf8");
  const sumFor = new Map(
    checksums
      .split("\n")
      .map((line) => line.trim().split(/\s+/))
      .filter((parts) => parts.length === 2 && /^[0-9a-f]{64}$/.test(parts[0]))
      .map(([hash, name]) => [name, hash]),
  );

  for (const { pkg, asset, exe } of PLATFORMS) {
    const buf = await download(asset);
    const expected = sumFor.get(asset);
    if (!expected) {
      throw new Error(`checksums.txt has no entry for ${asset}`);
    }
    const actual = createHash("sha256").update(buf).digest("hex");
    if (actual !== expected) {
      throw new Error(`checksum mismatch for ${asset}: got ${actual}, want ${expected}`);
    }

    const binDir = join(root, "platforms", pkg, "bin");
    await mkdir(binDir, { recursive: true });
    const dest = join(binDir, exe ? "tvault.exe" : "tvault");
    await writeFile(dest, buf);
    await chmod(dest, 0o755);

    const pkgJsonPath = join(root, "platforms", pkg, "package.json");
    const pkgJson = JSON.parse(await readFile(pkgJsonPath, "utf8"));
    pkgJson.version = version;
    await writeFile(pkgJsonPath, JSON.stringify(pkgJson, null, 2) + "\n");
    console.log(`packed ${pkg} <- ${asset} (${buf.length} bytes, sha256 ok)`);
  }

  const mainPath = join(root, "cli", "package.json");
  const main = JSON.parse(await readFile(mainPath, "utf8"));
  main.version = version;
  for (const { pkg } of PLATFORMS) {
    main.optionalDependencies[`@thelacanians/tinyvault-${pkg}`] = version;
  }
  await writeFile(mainPath, JSON.stringify(main, null, 2) + "\n");
  console.log(`main @thelacanians/tinyvault version -> ${version}`);
  console.log("done — run npm publish per package (platforms first, main last)");
}

main().catch((err) => {
  console.error(`pack.mjs failed: ${err.message}`);
  process.exit(1);
});
