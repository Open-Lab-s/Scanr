#!/usr/bin/env node

const { existsSync } = require("node:fs");
const { spawnSync } = require("node:child_process");
const { join } = require("node:path");

function binaryName() {
  return process.platform === "win32" ? "scanr.exe" : "scanr";
}

const binPath = join(__dirname, "..", "vendor", binaryName());

if (!existsSync(binPath)) {
  console.error("Scanr binary was not found.");
  console.error("Reinstall package: npm install -g scanr");
  process.exit(1);
}

const result = spawnSync(binPath, process.argv.slice(2), {
  stdio: "inherit",
  env: process.env,
});

if (typeof result.status === "number") {
  process.exit(result.status);
}

if (result.error) {
  console.error(`Failed to launch Scanr: ${result.error.message}`);
}
process.exit(1);
