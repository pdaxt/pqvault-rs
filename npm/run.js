#!/usr/bin/env node
const { execFileSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const binPath = path.join(__dirname, "bin", "pqvault");

if (!fs.existsSync(binPath)) {
  console.error("pqvault binary not found. Run: npm run postinstall");
  process.exit(1);
}

try {
  execFileSync(binPath, ["serve"], {
    stdio: "inherit",
    env: process.env,
  });
} catch (e) {
  process.exit(e.status || 1);
}
