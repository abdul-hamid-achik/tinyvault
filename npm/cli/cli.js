#!/usr/bin/env node
"use strict";

// Thin launcher for the TinyVault binary.
//
// npm installs this package on any platform; the matching optional dependency
// (@thelacanians/tinyvault-<platform>) carries the actual tvault binary for
// the host's OS/CPU. Everything else is pass-through: argv, stdin/stdout/
// stderr, signals, and exit status — so `tvault mcp` works over stdio exactly
// as if the binary were installed directly.

const { spawn } = require("node:child_process");
const path = require("node:path");

const platformKey = `${process.platform}-${process.arch}`;
const supported = [
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64",
  "linux-x64",
  "win32-arm64",
  "win32-x64",
];

let binPath;
try {
  const pkgDir = path.dirname(
    require.resolve(`@thelacanians/tinyvault-${platformKey}/package.json`),
  );
  binPath = path.join(
    pkgDir,
    "bin",
    process.platform === "win32" ? "tvault.exe" : "tvault",
  );
} catch {
  console.error(
    `tvault: no binary for platform ${platformKey}. ` +
      `Supported platforms: ${supported.join(", ")}. ` +
      "Reinstall with: npm install -g @thelacanians/tinyvault",
  );
  process.exit(1);
}

const child = spawn(binPath, process.argv.slice(2), { stdio: "inherit" });

child.on("error", (err) => {
  console.error(`tvault: failed to launch ${binPath}: ${err.message}`);
  process.exit(1);
});

child.on("exit", (code, signal) => {
  if (signal) {
    // Die with the same signal the child received, like a native binary would.
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code ?? 0);
});
