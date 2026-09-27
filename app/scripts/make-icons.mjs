/**
 * Regenerates app/build/icon.icns and app/build/icon.png from app/build/icon.svg.
 *
 * Uses @resvg/resvg-js rather than macOS `qlmanage` because qlmanage flattens
 * SVG transparency to white when rendering thumbnails — which put white squares
 * in the icon's rounded corners in the Dock. resvg preserves the alpha channel,
 * and being a normal dependency this runs identically on any platform.
 *
 * The outputs are committed so CI and other platforms never need to run this.
 * electron-builder picks icon.icns / icon.png up from buildResources: build.
 *
 *   bun run icons
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { Resvg } from "@resvg/resvg-js";

const here = fileURLToPath(new URL(".", import.meta.url));
const root = join(here, "..");
const src = join(root, "build", "icon.svg");

const work = mkdtempSync(join(tmpdir(), "tv-icons-"));
const master = join(work, "master.png");

try {
  const svg = readFileSync(src, "utf8");
  const rendered = new Resvg(svg, {
    fitTo: { mode: "width", value: 1024 },
    // Explicitly transparent; never let a rasterizer invent a background.
    background: "rgba(0, 0, 0, 0)"
  }).render();
  writeFileSync(master, rendered.asPng());

  const iconset = join(work, "icon.iconset");
  execFileSync("mkdir", ["-p", iconset]);

  // Apple's iconset contract: each logical size plus its @2x pixel size.
  const sizes = [
    [16, "icon_16x16.png"],
    [32, "icon_16x16@2x.png"],
    [32, "icon_32x32.png"],
    [64, "icon_32x32@2x.png"],
    [128, "icon_128x128.png"],
    [256, "icon_128x128@2x.png"],
    [256, "icon_256x256.png"],
    [512, "icon_256x256@2x.png"],
    [512, "icon_512x512.png"],
    [1024, "icon_512x512@2x.png"]
  ];
  for (const [px, name] of sizes) {
    execFileSync(
      "sips",
      ["-z", String(px), String(px), master, "--out", join(iconset, name)],
      { stdio: "pipe" }
    );
  }

  execFileSync("iconutil", ["-c", "icns", iconset, "-o", join(root, "build", "icon.icns")], {
    stdio: "pipe"
  });
  execFileSync("sips", ["-z", "512", "512", master, "--out", join(root, "build", "icon.png")], {
    stdio: "pipe"
  });

  const alpha = execFileSync("sips", ["-g", "hasAlpha", join(root, "build", "icon.png")], {
    encoding: "utf8"
  });
  console.log("wrote build/icon.icns and build/icon.png");
  console.log(alpha.trim().split("\n").pop());
} finally {
  rmSync(work, { recursive: true, force: true });
}
