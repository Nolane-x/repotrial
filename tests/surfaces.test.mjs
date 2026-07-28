import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyRepositoryFile, isAgentInstructionFile } from '../src/core/surfaces.mjs';

const INSTRUCTION_CASES = [
  ['AGENTS.md', 'agents'],
  ['packages/api/AGENTS.md', 'agents'],
  ['CLAUDE.md', 'claude'],
  ['.claude/CLAUDE.md', 'claude'],
  ['packages/api/CLAUDE.md', 'claude'],
  ['GEMINI.md', 'gemini'],
  ['.github/copilot-instructions.md', 'copilot'],
  ['.github/instructions/security.instructions.md', 'copilot'],
  ['.github/agents/security-reviewer.md', 'copilot'],
  ['.cursor/rules/security.mdc', 'cursor'],
  ['.cursorrules', 'cursor'],
  ['.clinerules/security.md', 'cline'],
  ['.clinerules', 'cline'],
  ['.windsurf/rules/security.md', 'windsurf'],
  ['.windsurfrules', 'windsurf'],
  ['.continue/rules/security.md', 'continue']
];

test('classifies current repository instruction surfaces across popular coding agents', () => {
  for (const [file, agent] of INSTRUCTION_CASES) {
    const classification = classifyRepositoryFile(file);
    assert.equal(classification.kind, 'instruction', file);
    assert.ok(classification.agents.includes(agent), `${file} should include ${agent}`);
    assert.equal(isAgentInstructionFile(file), true, file);
  }
});

test('does not classify ordinary markdown or generated reports as agent instructions', () => {
  for (const file of ['README.md', 'docs/security.md', '.repotrial/report.html', 'src/CLAUDE.md.js']) {
    assert.equal(isAgentInstructionFile(file), false, file);
    assert.equal(classifyRepositoryFile(file).kind, 'other', file);
  }
});

test('classifies known agent hook configuration files as agent configs', () => {
  for (const filename of ['.cursor/hooks.json', '.claude/hooks.yaml', '.continue/hooks.toml']) {
    assert.equal(classifyRepositoryFile(filename).kind, 'agent-config');
  }
});
