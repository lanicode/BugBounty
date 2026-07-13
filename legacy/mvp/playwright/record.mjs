import fs from 'fs';
import path from 'path';
import { chromium } from 'playwright';
import YAML from 'yaml';

const account = process.argv[2];
if (!['account-a', 'account-b'].includes(account)) {
  console.error('Usage: node playwright/record.mjs account-a|account-b');
  process.exit(1);
}

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const scope = YAML.parse(fs.readFileSync(path.join(root, 'config', 'scope.yaml'), 'utf8'));
const allowedHosts = new Set(scope.allowed_hosts || []);
if (allowedHosts.size === 0 || [...allowedHosts].some(h => h.includes('example.com'))) {
  console.error('Bitte zuerst config/scope.yaml mit dem echten autorisierten Scope ausfuellen.');
  process.exit(1);
}

const inputDir = path.join(root, 'input', account);
const profileDir = path.join(inputDir, 'profile');
fs.mkdirSync(inputDir, { recursive: true });
fs.mkdirSync(profileDir, { recursive: true });

const context = await chromium.launchPersistentContext(profileDir, {
  headless: false,
  recordHar: {
    path: path.join(inputDir, 'session.har'),
    mode: 'full',
    content: 'embed'
  }
});

context.on('page', page => {
  page.on('request', request => {
    try {
      const host = new URL(request.url()).hostname;
      if (!allowedHosts.has(host)) {
        console.log(`[OUT-OF-SCOPE beobachtet] ${host}`);
      }
    } catch {}
  });
});

const page = context.pages()[0] || await context.newPage();
const firstHost = [...allowedHosts][0];
await page.goto(`https://${firstHost}`, { waitUntil: 'domcontentloaded' }).catch(() => {});
console.log(`\nAufzeichnung fuer ${account} laeuft.`);
console.log('Bediene nur autorisierte Funktionen mit deinem eigenen Testkonto.');
console.log('Schliesse den Browser, um die HAR-Datei zu speichern.\n');

await new Promise(resolve => context.on('close', resolve));
