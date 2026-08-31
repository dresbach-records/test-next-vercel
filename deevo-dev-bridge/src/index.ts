import { createMcpHandler, McpServer } from '@modelcontextprotocol/server';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { toNodeHandler } from '@modelcontextprotocol/node';
import { createServer as createHttpServer } from 'node:http';
import { spawn } from 'node:child_process';
import { appendFile, mkdir, readFile, writeFile, unlink, readdir, stat, realpath } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import * as z from 'zod/v4';

type Permission = keyof typeof DEFAULT_PERMISSIONS;

const DEFAULT_PERMISSIONS = {
  'filesystem.read': true,
  'filesystem.write': true,
  'filesystem.delete': false,
  'terminal.cmd': false,
  'terminal.powershell': false,
  'terminal.bash': false,
  'npm.install': true,
  'npm.run': true,
  'git.status': true,
  'git.diff': true,
  'git.commit': false,
  'git.push': false,
  'docker.read': true,
  'docker.compose': false,
  'docker.exec': false,
  'system.env': false
} as const;

type Policy = {
  workspaceRoot: string;
  permissions: Partial<Record<Permission, boolean>>;
  allowedEnv: string[];
  auditFile: string;
};

function loadPolicy(): Policy {
  const file = process.env.DEEVO_POLICY ?? path.resolve(process.cwd(), 'config/permissions.json');
  const fallback: Policy = {
    workspaceRoot: process.env.WORKSPACE_ROOT ?? process.cwd(),
    permissions: { ...DEFAULT_PERMISSIONS },
    allowedEnv: [],
    auditFile: '.deevo/audit/events.jsonl'
  };
  try {
    const raw = JSON.parse(requirelessRead(file));
    return {
      ...fallback,
      ...raw,
      permissions: { ...fallback.permissions, ...(raw.permissions ?? {}) },
      workspaceRoot: expand(raw.workspaceRoot ?? fallback.workspaceRoot)
    };
  } catch {
    return fallback;
  }
}

function requirelessRead(file: string): string {
  const fs = require('node:fs');
  return fs.readFileSync(file, 'utf8');
}

function expand(value: string): string {
  return value.replace(/\$\{([^}]+)\}/g, (_, key) => process.env[key] ?? '');
}

const policy = loadPolicy();
policy.workspaceRoot = path.resolve(expand(policy.workspaceRoot));

async function audit(tool: string, input: unknown, result: 'allowed' | 'denied' | 'error', detail?: string) {
  const auditPath = path.resolve(policy.workspaceRoot, policy.auditFile);
  await mkdir(path.dirname(auditPath), { recursive: true });
  await appendFile(auditPath, JSON.stringify({
    timestamp: new Date().toISOString(),
    tool,
    result,
    input: redact(input),
    detail
  }) + '\n');
}

function redact(input: unknown): unknown {
  if (!input || typeof input !== 'object') return input;
  const clone = JSON.parse(JSON.stringify(input));
  for (const key of ['password', 'token', 'secret', 'apiKey', 'authorization']) {
    if (key in clone) clone[key] = '[REDACTED]';
  }
  return clone;
}

function allowed(permission: Permission): boolean {
  return policy.permissions[permission] === true;
}

async function guard(permission: Permission, tool: string, input: unknown) {
  if (!allowed(permission)) {
    await audit(tool, input, 'denied', `permission ${permission} is disabled`);
    throw new Error(`Permission denied: ${permission}`);
  }
}

async function safePath(relativePath: string, forWrite = false): Promise<string> {
  if (path.isAbsolute(relativePath)) throw new Error('Absolute paths are not allowed.');
  const candidate = path.resolve(policy.workspaceRoot, relativePath);
  const root = await realpath(policy.workspaceRoot);
  try {
    const existing = await realpath(candidate);
    if (existing !== root && !existing.startsWith(root + path.sep)) throw new Error('Path escapes workspace.');
    return existing;
  } catch {
    if (!forWrite) throw new Error('Path does not exist.');
    const parent = await realpath(path.dirname(candidate));
    if (parent !== root && !parent.startsWith(root + path.sep)) throw new Error('Path escapes workspace.');
    return candidate;
  }
}

function text(result: unknown) {
  return { content: [{ type: 'text' as const, text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }] };
}

function run(command: string, args: string[], cwd = policy.workspaceRoot, env?: NodeJS.ProcessEnv): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, ...env },
      shell: false,
      windowsHide: true
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => stdout += d.toString());
    child.stderr.on('data', d => stderr += d.toString());
    child.on('error', reject);
    child.on('close', code => resolve({ code: code ?? -1, stdout, stderr }));
  });
}

function createServer() {
  const server = new McpServer({ name: 'deevo-dev-bridge', version: '0.1.0' });

  server.registerTool('workspace.list', {
    description: 'List files and directories inside the controlled workspace.',
    inputSchema: z.object({ path: z.string().default('.') })
  }, async ({ path: relative }) => {
    await guard('filesystem.read', 'workspace.list', { path: relative });
    const target = await safePath(relative);
    const entries = await readdir(target, { withFileTypes: true });
    await audit('workspace.list', { path: relative }, 'allowed');
    return text(entries.map(e => ({ name: e.name, type: e.isDirectory() ? 'directory' : 'file' })));
  });

  server.registerTool('workspace.read', {
    description: 'Read a UTF-8 text file from the controlled workspace.',
    inputSchema: z.object({ path: z.string() })
  }, async ({ path: relative }) => {
    await guard('filesystem.read', 'workspace.read', { path: relative });
    const target = await safePath(relative);
    const content = await readFile(target, 'utf8');
    await audit('workspace.read', { path: relative }, 'allowed');
    return text(content);
  });

  server.registerTool('workspace.write', {
    description: 'Create or replace a UTF-8 text file inside the controlled workspace.',
    inputSchema: z.object({ path: z.string(), content: z.string() })
  }, async ({ path: relative, content }) => {
    await guard('filesystem.write', 'workspace.write', { path: relative });
    const target = await safePath(relative, true);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, content, 'utf8');
    await audit('workspace.write', { path: relative }, 'allowed');
    return text(`Written: ${relative}`);
  });

  server.registerTool('workspace.delete', {
    description: 'Delete a file from the controlled workspace. Disabled by default.',
    inputSchema: z.object({ path: z.string() })
  }, async ({ path: relative }) => {
    await guard('filesystem.delete', 'workspace.delete', { path: relative });
    const target = await safePath(relative);
    const info = await stat(target);
    if (!info.isFile()) throw new Error('Only files can be deleted by this tool.');
    await unlink(target);
    await audit('workspace.delete', { path: relative }, 'allowed');
    return text(`Deleted: ${relative}`);
  });

  server.registerTool('npm.install', {
    description: 'Run npm install in the controlled workspace.',
    inputSchema: z.object({ args: z.array(z.string()).default([]) })
  }, async ({ args }) => {
    await guard('npm.install', 'npm.install', { args });
    const result = await run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['install', ...args]);
    await audit('npm.install', { args }, result.code === 0 ? 'allowed' : 'error', result.stderr.slice(-2000));
    return text(result);
  });

  server.registerTool('npm.run', {
    description: 'Run an npm script such as test, build or lint.',
    inputSchema: z.object({ script: z.string().regex(/^[a-zA-Z0-9:_-]+$/), args: z.array(z.string()).default([]) })
  }, async ({ script, args }) => {
    await guard('npm.run', 'npm.run', { script, args });
    const result = await run(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', script, ...(args.length ? ['--', ...args] : [])]);
    await audit('npm.run', { script, args }, result.code === 0 ? 'allowed' : 'error', result.stderr.slice(-2000));
    return text(result);
  });

  server.registerTool('terminal.cmd', {
    description: 'Execute a Windows CMD command. Disabled by default.',
    inputSchema: z.object({ command: z.string() })
  }, async ({ command }) => {
    await guard('terminal.cmd', 'terminal.cmd', { command });
    if (process.platform !== 'win32') throw new Error('CMD is only available on Windows.');
    const result = await run('cmd.exe', ['/d', '/s', '/c', command]);
    await audit('terminal.cmd', { command }, result.code === 0 ? 'allowed' : 'error');
    return text(result);
  });

  server.registerTool('terminal.powershell', {
    description: 'Execute a PowerShell command. Disabled by default.',
    inputSchema: z.object({ command: z.string() })
  }, async ({ command }) => {
    await guard('terminal.powershell', 'terminal.powershell', { command });
    const executable = process.platform === 'win32' ? 'powershell.exe' : 'pwsh';
    const result = await run(executable, ['-NoProfile', '-NonInteractive', '-Command', command]);
    await audit('terminal.powershell', { command }, result.code === 0 ? 'allowed' : 'error');
    return text(result);
  });

  server.registerTool('terminal.bash', {
    description: 'Execute a Bash command. Disabled by default.',
    inputSchema: z.object({ command: z.string() })
  }, async ({ command }) => {
    await guard('terminal.bash', 'terminal.bash', { command });
    const result = await run('bash', ['-lc', command]);
    await audit('terminal.bash', { command }, result.code === 0 ? 'allowed' : 'error');
    return text(result);
  });

  server.registerTool('git.status', {
    description: 'Read git status for the controlled workspace.',
    inputSchema: z.object({ args: z.array(z.string()).default([]) })
  }, async ({ args }) => {
    await guard('git.status', 'git.status', { args });
    return text(await run('git', ['status', '--short', ...args]));
  });

  server.registerTool('git.diff', {
    description: 'Read the git diff for the controlled workspace.',
    inputSchema: z.object({ args: z.array(z.string()).default([]) })
  }, async ({ args }) => {
    await guard('git.diff', 'git.diff', { args });
    return text(await run('git', ['diff', ...args]));
  });

  server.registerTool('git.commit', {
    description: 'Create a git commit. Disabled by default.',
    inputSchema: z.object({ message: z.string().min(1) })
  }, async ({ message }) => {
    await guard('git.commit', 'git.commit', { message });
    const result = await run('git', ['add', '-A']);
    if (result.code !== 0) return text(result);
    const commit = await run('git', ['commit', '-m', message]);
    await audit('git.commit', { message }, commit.code === 0 ? 'allowed' : 'error', commit.stderr);
    return text(commit);
  });

  server.registerTool('git.push', {
    description: 'Push the current branch to its configured remote. Disabled by default.',
    inputSchema: z.object({ remote: z.string().default('origin'), branch: z.string().optional() })
  }, async ({ remote, branch }) => {
    await guard('git.push', 'git.push', { remote, branch });
    const args = ['push', remote];
    if (branch) args.push(branch);
    const result = await run('git', args);
    await audit('git.push', { remote, branch }, result.code === 0 ? 'allowed' : 'error', result.stderr);
    return text(result);
  });

  server.registerTool('docker.ps', {
    description: 'List Docker containers. Read-only and enabled by default.',
    inputSchema: z.object({ all: z.boolean().default(false) })
  }, async ({ all }) => {
    await guard('docker.read', 'docker.ps', { all });
    return text(await run('docker', ['ps', ...(all ? ['-a'] : [])]));
  });

  server.registerTool('docker.logs', {
    description: 'Read Docker container logs.',
    inputSchema: z.object({ container: z.string(), tail: z.number().int().positive().max(5000).default(200) })
  }, async ({ container, tail }) => {
    await guard('docker.read', 'docker.logs', { container, tail });
    return text(await run('docker', ['logs', '--tail', String(tail), container]));
  });

  server.registerTool('docker.compose', {
    description: 'Run Docker Compose up/down/restart. Disabled by default.',
    inputSchema: z.object({ action: z.enum(['up', 'down', 'restart']), services: z.array(z.string()).default([]) })
  }, async ({ action, services }) => {
    await guard('docker.compose', 'docker.compose', { action, services });
    const args = ['compose', action];
    if (action === 'up') args.push('-d');
    args.push(...services);
    const result = await run('docker', args);
    await audit('docker.compose', { action, services }, result.code === 0 ? 'allowed' : 'error', result.stderr);
    return text(result);
  });

  server.registerTool('docker.exec', {
    description: 'Execute a command inside a running Docker container. Disabled by default.',
    inputSchema: z.object({ container: z.string(), command: z.array(z.string()).min(1) })
  }, async ({ container, command }) => {
    await guard('docker.exec', 'docker.exec', { container, command });
    const result = await run('docker', ['exec', container, ...command]);
    await audit('docker.exec', { container, command }, result.code === 0 ? 'allowed' : 'error');
    return text(result);
  });

  server.registerTool('system.env', {
    description: 'Read explicitly allowlisted environment variables. Disabled by default.',
    inputSchema: z.object({ name: z.string().regex(/^[A-Z_][A-Z0-9_]*$/) })
  }, async ({ name }) => {
    await guard('system.env', 'system.env', { name });
    if (!policy.allowedEnv.includes(name)) throw new Error(`Environment variable is not allowlisted: ${name}`);
    await audit('system.env', { name }, 'allowed');
    return text({ name, value: process.env[name] ?? null });
  });

  return server;
}

async function main() {
  const mode = process.argv.includes('--http') ? 'http' : 'stdio';
  if (mode === 'stdio') {
    serveStdio(() => createServer());
    return;
  }

  const port = Number(process.env.PORT ?? 4318);
  const token = process.env.DEEVO_MCP_TOKEN;
  if (!token) throw new Error('DEEVO_MCP_TOKEN is required for HTTP mode.');

  const handler = createMcpHandler(() => createServer());
  const nodeHandler = toNodeHandler(handler, { onerror: error => console.error('[deevo-dev-bridge]', error) });
  const http = createHttpServer((req, res) => {
    const auth = req.headers.authorization;
    if (auth !== `Bearer ${token}`) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Unauthorized' }));
      return;
    }
    if (req.url !== '/mcp' && req.url !== '/mcp/') {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    void nodeHandler(req, res);
  });
  http.listen(port, '127.0.0.1', () => console.error(`DEEVO Dev Bridge listening on http://127.0.0.1:${port}/mcp`));
}

void main();
