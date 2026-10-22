#!/usr/bin/env node
// One-command demo: starts the approval server, walks you through registering a passkey,
// adds the example MCP servers to Claude Code, and shows approvals live as they happen.
//
//   npm run demo                 full setup, then live feed
//   npm run demo -- --no-install don't touch Claude Code's MCP config; just print the commands
//   npm run demo -- --no-open    don't open the browser

import { execFileSync, spawn } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, openSync, readSync, closeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const args = new Set(process.argv.slice(2));
const install = !args.has('--no-install');
const openBrowser = !args.has('--no-open');
const port = Number(process.env.PORT ?? 4747);
const origin = `http://localhost:${port}`;
const dataDir = resolve(process.env.EZCHECK_DATA_DIR ?? join(root, '.ezcheck'));
const tsx = join(root, 'node_modules', '.bin', 'tsx');

const c = (code) => (s) => (process.stdout.isTTY ? `\x1b[${code}m${s}\x1b[0m` : s);
const [bold, dim, green, red, yellow, cyan] = [c('1'), c('2'), c('32'), c('31'), c('33'), c('36')];
const step = (n, text) => console.log(`\n${bold(cyan(`[${n}/4]`))} ${bold(text)}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (!existsSync(tsx)) {
  console.error(red('Dependencies missing. Run `npm install` first.'));
  process.exit(1);
}

// 1. Build the SDK and pick a stable agent token (kept in the data dir so Claude Code's config stays valid).
step(1, 'Building the SDK');
execFileSync(join(root, 'node_modules', '.bin', 'tsc'), ['-p', join(root, 'packages/mcp-sdk/tsconfig.json')], {
  stdio: 'inherit',
});
mkdirSync(dataDir, { recursive: true });
const tokenFile = join(dataDir, 'agent-token');
const token =
  process.env.EZCHECK_AGENT_TOKEN ??
  (existsSync(tokenFile) ? readFileSync(tokenFile, 'utf8').trim() : randomBytes(24).toString('base64url'));
writeFileSync(tokenFile, token, { mode: 0o600 });

// 2. Start the approval server.
step(2, `Starting the approval server on ${origin}`);
const server = spawn(tsx, [join(root, 'packages/approval-server/src/main.ts')], {
  env: {
    ...process.env,
    NODE_NO_WARNINGS: '1', // keep the live feed clean for screen recording
    PORT: String(port),
    EZCHECK_AGENT_TOKEN: token,
    EZCHECK_DATA_DIR: dataDir,
    EZCHECK_APPROVAL_TTL_MS: process.env.EZCHECK_APPROVAL_TTL_MS ?? '300000', // 5 min: room to talk on camera
  },
  stdio: ['ignore', 'ignore', 'inherit'],
});
const stop = () => {
  server.kill();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
server.on('exit', (code) => {
  console.error(red(`Approval server exited (${code}). Is port ${port} already in use?`));
  process.exit(1);
});

const api = async (path, opts = {}) => {
  const res = await fetch(origin + path, opts);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
};
for (let i = 0; ; i++) {
  try {
    await api('/webauthn/status');
    break;
  } catch {
    if (i > 100) throw new Error('Approval server did not start');
    await sleep(200);
  }
}
console.log(green('  running'));

// 3. Passkey registration (once; it's kept in the data dir).
step(3, 'Passkey');
if ((await api('/webauthn/status')).registered) {
  console.log(green('  already registered'));
} else {
  console.log(`  Open ${bold(`${origin}/register`)} and click ${bold('Create passkey')} (Touch ID / Windows Hello).`);
  if (openBrowser) openUrl(`${origin}/register`);
  process.stdout.write(dim('  waiting'));
  while (!(await api('/webauthn/status')).registered) {
    process.stdout.write(dim('.'));
    await sleep(1000);
  }
  console.log(green('\n  registered'));
}
const passkeys = JSON.stringify(await api('/api/passkeys', { headers: { authorization: `Bearer ${token}` } }));

// 4. Add the examples to Claude Code with the token and pinned passkey.
step(4, 'Claude Code MCP servers');
const servers = [
  ['ez-check-stripe', 'examples/mcp-stripe-guard/src/main.ts'],
  ['ez-check-backup', 'examples/backup-demo/src/main.ts'],
];
for (const [name, entry] of servers) {
  const addArgs = [
    'mcp', 'add', name, '--scope', 'user',
    '-e', `EZCHECK_AGENT_TOKEN=${token}`,
    '-e', `EZCHECK_URL=${origin}`,
    '-e', `EZCHECK_PASSKEYS=${passkeys}`,
    '--', tsx, join(root, entry),
  ];
  if (!install) {
    console.log(`  claude ${addArgs.map(shellQuote).join(' ')}`);
    continue;
  }
  try {
    try {
      execFileSync('claude', ['mcp', 'remove', name, '--scope', 'user'], { stdio: 'ignore' });
    } catch {
      // not added yet
    }
    execFileSync('claude', addArgs, { stdio: 'ignore' });
    console.log(green(`  added ${name}`));
  } catch {
    console.log(yellow(`  couldn't run \`claude\`; add it yourself:`));
    console.log(`  claude ${addArgs.map(shellQuote).join(' ')}`);
  }
}

console.log(`
${bold('Ready.')} In a new terminal, start ${bold('claude')} and try:
  ${cyan('"Show me recent Stripe charges"')}            runs instantly (low risk)
  ${cyan('"Refund $500 of the Team plan charge"')}      pauses for your passkey
  ${cyan('"Delete the oldest backup"')}                 pauses for your passkey

Live approvals ${dim(`(${join(dataDir, 'audit.jsonl')})`)}. Ctrl+C to stop.
`);

// Live feed of the audit log, so the video shows each request and decision as it lands.
const auditFile = join(dataDir, 'audit.jsonl');
let offset = existsSync(auditFile) ? statSync(auditFile).size : 0;
const icons = { requested: yellow('⏸  requested'), approved: green('✓  approved '), denied: red('✗  denied   '), expired: dim('⌛ expired  ') };
setInterval(() => {
  if (!existsSync(auditFile)) return;
  const size = statSync(auditFile).size;
  if (size <= offset) return;
  const fd = openSync(auditFile, 'r');
  const buf = Buffer.alloc(size - offset);
  readSync(fd, buf, 0, buf.length, offset);
  closeSync(fd);
  offset = size;
  for (const line of buf.toString('utf8').split('\n').filter(Boolean)) {
    const e = JSON.parse(line);
    const time = new Date(e.at).toLocaleTimeString();
    console.log(`${dim(time)}  ${icons[e.event] ?? e.event}  ${bold(e.tool)}  ${e.summary}`);
  }
}, 300);

function openUrl(url) {
  const [cmd, cmdArgs] =
    process.platform === 'darwin' ? ['open', [url]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', url]] : ['xdg-open', [url]];
  spawn(cmd, cmdArgs, { stdio: 'ignore', detached: true }).unref();
}

function shellQuote(s) {
  return /^[\w@%+=:,./-]+$/.test(s) ? s : `'${s.replaceAll("'", `'\\''`)}'`;
}
