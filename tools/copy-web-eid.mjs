import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const moduleRoot = path.join(root, 'node_modules');
const destination = path.join(root, 'public', 'javascript', 'web-eid.js');

function findFile(dir, wanted) {
  if (!fs.existsSync(dir)) return null;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findFile(full, wanted);
      if (found) return found;
    } else if (entry.isFile() && entry.name === wanted && full.includes(`${path.sep}dist${path.sep}es${path.sep}`)) {
      return full;
    }
  }
  return null;
}

const source = findFile(moduleRoot, 'web-eid.js');
if (!source) {
  console.error('Could not locate dist/es/web-eid.js after npm install.');
  process.exit(1);
}

fs.mkdirSync(path.dirname(destination), { recursive: true });
fs.copyFileSync(source, destination);
console.log(`Copied ${source}`);
console.log(`     -> ${destination}`);
