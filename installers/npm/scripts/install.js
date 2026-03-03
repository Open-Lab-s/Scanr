#!/usr/bin/env node

const { createWriteStream } = require("node:fs");
const { chmodSync, mkdirSync, readFileSync } = require("node:fs");
const { join } = require("node:path");
const { get } = require("node:https");

function loadVersion() {
  const packageJson = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));
  return packageJson.version;
}

function binaryName() {
  return process.platform === "win32" ? "scanr.exe" : "scanr";
}

function targetAssetName() {
  const arch = process.arch;
  const platform = process.platform;

  if (platform === "linux" && arch === "x64") return "scanr-x86_64-unknown-linux-gnu";
  if (platform === "linux" && arch === "arm64") return "scanr-aarch64-unknown-linux-gnu";
  if (platform === "darwin" && arch === "x64") return "scanr-x86_64-apple-darwin";
  if (platform === "darwin" && arch === "arm64") return "scanr-aarch64-apple-darwin";
  if (platform === "win32" && arch === "x64") return "scanr-x86_64-pc-windows-msvc.exe";

  return null;
}

function download(url, destination, redirects = 0) {
  return new Promise((resolve, reject) => {
    if (redirects > 5) {
      reject(new Error("too many redirects"));
      return;
    }

    const request = get(
      url,
      {
        headers: {
          "user-agent": "scanr-npm-installer",
        },
      },
      (response) => {
        if (
          response.statusCode &&
          response.statusCode >= 300 &&
          response.statusCode < 400 &&
          response.headers.location
        ) {
          download(response.headers.location, destination, redirects + 1)
            .then(resolve)
            .catch(reject);
          return;
        }

        if (response.statusCode !== 200) {
          reject(new Error(`download failed (${response.statusCode})`));
          return;
        }

        const file = createWriteStream(destination, { mode: 0o755 });
        response.pipe(file);
        file.on("finish", () => file.close(resolve));
        file.on("error", reject);
      },
    );

    request.on("error", reject);
  });
}

async function main() {
  const assetName = targetAssetName();
  if (!assetName) {
    console.warn("Scanr npm installer: unsupported platform/arch.");
    console.warn("Install from source with cargo: cargo install --path crates/scanr-cli");
    return;
  }

  const version = loadVersion();
  const base =
    process.env.SCANR_NPM_DOWNLOAD_BASE ||
    `https://github.com/Open-Lab-s/Scanr/releases/download/v${version}`;
  const url = `${base}/${assetName}`;
  const vendorDir = join(__dirname, "..", "vendor");
  const output = join(vendorDir, binaryName());

  mkdirSync(vendorDir, { recursive: true });
  await download(url, output);
  if (process.platform !== "win32") {
    chmodSync(output, 0o755);
  }

  console.log(`Scanr binary installed: ${output}`);
}

main().catch((error) => {
  console.error(`Scanr npm installer failed: ${error.message}`);
  console.error("Install from source with cargo: cargo install --path crates/scanr-cli");
  process.exit(1);
});
