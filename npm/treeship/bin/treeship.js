#!/usr/bin/env node
'use strict';

const { execFileSync } = require('child_process');
const os = require('os');

const PLATFORM_MAP = {
  'linux-x64':    '@treeship/cli-linux-x64',
  'darwin-arm64': '@treeship/cli-darwin-arm64',
  'darwin-x64':   '@treeship/cli-darwin-x64',
};

const key = `${os.platform()}-${os.arch()}`;
const pkg = PLATFORM_MAP[key];

if (!pkg) {
  console.error(`treeship: unsupported platform ${key}`);
  console.error('Install via: cargo install treeship-cli');
  process.exit(1);
}

let binaryPath;
try {
  binaryPath = require(`${pkg}/binary`);
} catch {
  console.error(`treeship: platform package ${pkg} not found`);
  console.error('Try: npm install -g treeship');
  process.exit(1);
}

try {
  execFileSync(binaryPath, process.argv.slice(2), {
    stdio: 'inherit',
    env: process.env,
  });
} catch (e) {
  process.exit(e.status ?? 1);
}
