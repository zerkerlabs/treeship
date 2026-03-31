const https = require('https');
const fs = require('fs');
const path = require('path');

const VERSION = require('./package.json').version;
const BINARY_NAME = 'treeship-darwin-x86_64';
const URL = 'https://github.com/zerkerlabs/treeship/releases/download/v' + VERSION + '/' + BINARY_NAME;
const DEST = path.join(__dirname, 'bin', 'treeship');

if (fs.existsSync(DEST)) process.exit(0);

fs.mkdirSync(path.join(__dirname, 'bin'), { recursive: true });

console.log('treeship: downloading ' + BINARY_NAME + '...');

function download(url) {
  https.get(url, (res) => {
    if (res.statusCode === 302 || res.statusCode === 301) {
      download(res.headers.location);
      return;
    }
    if (res.statusCode !== 200) {
      console.error('treeship: download failed (' + res.statusCode + ')');
      console.error('Install manually: cargo install treeship-cli');
      process.exit(0);
    }
    const file = fs.createWriteStream(DEST);
    res.pipe(file);
    file.on('finish', () => {
      file.close();
      fs.chmodSync(DEST, 0o755);
      console.log('treeship: installed');
    });
  }).on('error', () => {
    console.error('treeship: download failed');
    console.error('Install manually: cargo install treeship-cli');
    process.exit(0);
  });
}

download(URL);
