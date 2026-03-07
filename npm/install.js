#!/usr/bin/env node
const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");
const https = require("https");

const VERSION = "2.1.0";
const REPO = "pdaxt/pqvault-rs";
const BIN_NAME = "pqvault";

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();

  const platformMap = {
    darwin: "apple-darwin",
    linux: "unknown-linux-gnu",
  };

  const archMap = {
    arm64: "aarch64",
    x64: "x86_64",
  };

  const p = platformMap[platform];
  const a = archMap[arch];

  if (!p || !a) {
    console.error(`Unsupported platform: ${platform}-${arch}`);
    console.error("Build from source: https://github.com/pdaxt/pqvault-rs");
    process.exit(1);
  }

  return `${a}-${p}`;
}

function download(url) {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return download(res.headers.location).then(resolve).catch(reject);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`HTTP ${res.statusCode}`));
        }
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => resolve(Buffer.concat(chunks)));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

async function main() {
  const target = getPlatform();
  const binDir = path.join(__dirname, "bin");

  // Check if binary already exists
  const binPath = path.join(binDir, BIN_NAME);
  if (fs.existsSync(binPath)) {
    console.log(`pqvault binary already exists at ${binPath}`);
    return;
  }

  // Try GitHub release first
  const releaseUrl = `https://github.com/${REPO}/releases/download/v${VERSION}/${BIN_NAME}-${target}.tar.gz`;
  console.log(`Downloading pqvault v${VERSION} for ${target}...`);

  try {
    const data = await download(releaseUrl);
    fs.mkdirSync(binDir, { recursive: true });
    const tarPath = path.join(binDir, "pqvault.tar.gz");
    fs.writeFileSync(tarPath, data);
    execSync(`tar xzf pqvault.tar.gz`, { cwd: binDir });
    fs.unlinkSync(tarPath);
    fs.chmodSync(binPath, 0o755);
    console.log(`Installed pqvault to ${binPath}`);
  } catch (e) {
    console.warn(`Pre-built binary not available for ${target}: ${e.message}`);
    console.log("Attempting to build from source (requires Rust toolchain)...");

    try {
      execSync("cargo --version", { stdio: "ignore" });
      const srcDir = path.join(os.tmpdir(), `pqvault-${VERSION}`);
      execSync(`git clone --depth 1 --branch v${VERSION} https://github.com/${REPO}.git ${srcDir}`, { stdio: "inherit" });
      execSync("cargo build --release -p pqvault-mcp", { cwd: srcDir, stdio: "inherit" });
      fs.mkdirSync(binDir, { recursive: true });
      fs.copyFileSync(path.join(srcDir, "target/release/pqvault"), binPath);
      fs.chmodSync(binPath, 0o755);
      console.log(`Built and installed pqvault to ${binPath}`);
    } catch (buildErr) {
      console.error("Failed to build from source. Install Rust: https://rustup.rs");
      console.error("Or build manually: git clone https://github.com/pdaxt/pqvault-rs && cargo build --release");
      process.exit(1);
    }
  }
}

main().catch((err) => {
  console.error("Installation failed:", err.message);
  process.exit(1);
});
