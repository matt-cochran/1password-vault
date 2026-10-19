import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const workflow = new URL('../.github/workflows/ci.yml', import.meta.url);

function concurrencyGroupTemplate(contents: string): string {
  const match = contents.match(/^concurrency:\s*\n\s+group:\s*(.+?)\s*$/m);
  if (!match) throw new Error('ci.yml has no concurrency.group');
  return match[1];
}

function renderConcurrencyGroup(template: string, github: Record<string, unknown>): string {
  const javascript = template.replace(/\$\{\{\s*([\s\S]*?)\s*\}\}/g, '${$1}');
  return new Function('github', `return \`${javascript}\`;`)(github) as string;
}

test('a release.yml call to ci.yml lands in a different concurrency group than a direct run', () => {
  const template = concurrencyGroupTemplate(readFileSync(workflow, 'utf8'));
  const direct = renderConcurrencyGroup(template, { workflow: 'CI', event: { pull_request: {} }, ref: 'refs/heads/staging' });
  const called = renderConcurrencyGroup(template, { workflow: 'Release', event: { pull_request: {} }, ref: 'refs/heads/staging' });
  assert.notEqual(direct, called);
});
