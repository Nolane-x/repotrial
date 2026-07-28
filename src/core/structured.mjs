import path from 'node:path';

const DEFAULT_LIMITS = Object.freeze({
  maxDepth: 64,
  maxNodes: 50_000,
  maxAliases: 256,
  maxScalarBytes: 1024 * 1024
});

class ParseFailure extends Error {
  constructor(code, message, line = null) {
    super(message);
    this.code = code;
    this.line = line;
  }
}

class AliasRef {
  constructor(name, line) {
    this.name = name;
    this.line = line;
  }
}

export function parseStructuredConfig(content, filename = '', options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...options };
  const format = detectFormat(filename, content);
  try {
    let value;
    if (format === 'json') value = parseJson(content, limits);
    else if (format === 'yaml') value = parseYaml(content, limits);
    else if (format === 'toml') value = parseToml(content, limits);
    else throw new ParseFailure('unsupported-format', `Unsupported structured config format: ${filename || 'unknown'}`);
    return { format, value, diagnostics: [] };
  } catch (error) {
    const failure = error instanceof ParseFailure
      ? error
      : new ParseFailure('syntax-error', error instanceof Error ? error.message : String(error));
    return {
      format,
      value: null,
      diagnostics: [{ code: failure.code, message: failure.message, ...(failure.line ? { line: failure.line } : {}) }]
    };
  }
}

function detectFormat(filename, content) {
  const extension = path.extname(String(filename)).toLowerCase();
  if (extension === '.json' || extension === '.jsonc') return 'json';
  if (extension === '.yaml' || extension === '.yml') return 'yaml';
  if (extension === '.toml' || /(?:^|\/)(?:Cargo|poetry|uv)\.lock$/i.test(String(filename))) return 'toml';
  const trimmed = String(content).trimStart();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) return 'json';
  return 'yaml';
}

function parseJson(content, limits) {
  let value;
  try { value = JSON.parse(normalizeJsonComments(String(content))); }
  catch (error) { throw new ParseFailure('syntax-error', error.message); }
  assertBounded(value, limits);
  return value;
}


function normalizeJsonComments(input) {
  const chars = [...input];
  let inString = false;
  let escaped = false;
  let lineComment = false;
  let blockComment = false;
  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index];
    const next = chars[index + 1];
    if (lineComment) {
      if (char === '\n' || char === '\r') lineComment = false;
      else chars[index] = ' ';
      continue;
    }
    if (blockComment) {
      if (char === '*' && next === '/') {
        chars[index] = ' ';
        chars[index + 1] = ' ';
        index += 1;
        blockComment = false;
      } else if (char !== '\n' && char !== '\r') chars[index] = ' ';
      continue;
    }
    if (inString) {
      if (escaped) { escaped = false; continue; }
      if (char === '\\') { escaped = true; continue; }
      if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; continue; }
    if (char === '/' && next === '/') {
      chars[index] = ' ';
      chars[index + 1] = ' ';
      index += 1;
      lineComment = true;
      continue;
    }
    if (char === '/' && next === '*') {
      chars[index] = ' ';
      chars[index + 1] = ' ';
      index += 1;
      blockComment = true;
    }
  }
  if (blockComment) throw new ParseFailure('syntax-error', 'Unterminated JSON block comment.');

  inString = false;
  escaped = false;
  for (let index = 0; index < chars.length; index += 1) {
    const char = chars[index];
    if (inString) {
      if (escaped) { escaped = false; continue; }
      if (char === '\\') { escaped = true; continue; }
      if (char === '"') inString = false;
      continue;
    }
    if (char === '"') { inString = true; continue; }
    if (char !== ',') continue;
    let lookahead = index + 1;
    while (lookahead < chars.length && /\s/.test(chars[lookahead])) lookahead += 1;
    if (chars[lookahead] === '}' || chars[lookahead] === ']') chars[index] = ' ';
  }
  return chars.join('');
}

function parseYaml(content, limits) {
  const state = {
    lines: tokenizeYamlLines(String(content)),
    index: 0,
    anchors: new Map(),
    aliases: 0,
    nodes: 0,
    limits
  };
  if (!state.lines.length) return {};
  const value = parseYamlBlock(state, state.lines[0].indent, 0);
  if (state.index < state.lines.length) {
    const line = state.lines[state.index];
    throw new ParseFailure('syntax-error', `Unexpected YAML content at line ${line.line}`, line.line);
  }
  return resolveYamlAliases(value, state);
}

function tokenizeYamlLines(content) {
  const physical = content.replace(/^\uFEFF/, '').split(/\r?\n/);
  const lines = [];
  for (let index = 0; index < physical.length; index += 1) {
    const raw = physical[index];
    if (/^\s*(?:#.*)?$/.test(raw) || /^\s*(?:---|\.\.\.)\s*$/.test(raw)) continue;
    if (/^\s*\t/.test(raw)) throw new ParseFailure('syntax-error', 'Tabs are not allowed for YAML indentation.', index + 1);
    const indent = raw.match(/^ */)[0].length;
    lines.push({ indent, text: stripComment(raw.slice(indent)).trimEnd(), raw, line: index + 1, physicalIndex: index });
  }
  return lines;
}

function parseYamlBlock(state, indent, depth) {
  checkDepth(state, depth);
  const first = state.lines[state.index];
  if (!first || first.indent < indent) return null;
  return first.indent === indent && /^-(?:\s|$)/.test(first.text)
    ? parseYamlSequence(state, indent, depth)
    : parseYamlMap(state, indent, depth);
}

function parseYamlMap(state, indent, depth) {
  const result = {};
  while (state.index < state.lines.length) {
    const line = state.lines[state.index];
    if (line.indent < indent) break;
    if (line.indent > indent) throw new ParseFailure('syntax-error', `Unexpected indentation at line ${line.line}`, line.line);
    if (/^-(?:\s|$)/.test(line.text)) break;
    const split = findYamlKeySeparator(line.text);
    if (split < 0) throw new ParseFailure('syntax-error', `Expected a mapping key at line ${line.line}`, line.line);
    const key = parseKey(line.text.slice(0, split).trim(), line.line);
    if (Object.hasOwn(result, key)) throw new ParseFailure('duplicate-key', `Duplicate YAML key "${key}" at line ${line.line}`, line.line);
    let rawValue = line.text.slice(split + 1).trim();
    state.index += 1;
    const anchor = takeAnchor(rawValue);
    if (anchor) rawValue = anchor.rest;
    let value;
    if (rawValue === '|' || rawValue === '>' || /^[|>][+-]?$/.test(rawValue)) {
      value = parseYamlBlockScalar(state, indent, rawValue[0]);
    } else if (!rawValue) {
      const next = state.lines[state.index];
      value = next && next.indent > indent ? parseYamlBlock(state, next.indent, depth + 1) : null;
    } else {
      value = parseInlineValue(rawValue, { syntax: 'yaml', line: line.line, limits: state.limits, depth: depth + 1, state });
    }
    countNode(state);
    result[key] = value;
    if (anchor) {
      if (state.anchors.has(anchor.name)) throw new ParseFailure('duplicate-anchor', `Duplicate YAML anchor &${anchor.name}`, line.line);
      state.anchors.set(anchor.name, value);
    }
  }
  return result;
}

function parseYamlSequence(state, indent, depth) {
  const result = [];
  while (state.index < state.lines.length) {
    const line = state.lines[state.index];
    if (line.indent < indent) break;
    if (line.indent !== indent || !/^-(?:\s|$)/.test(line.text)) break;
    let rawValue = line.text.replace(/^-(?:\s+|$)/, '');
    state.index += 1;
    const anchor = takeAnchor(rawValue);
    if (anchor) rawValue = anchor.rest;
    let value;
    if (!rawValue) {
      const next = state.lines[state.index];
      value = next && next.indent > indent ? parseYamlBlock(state, next.indent, depth + 1) : null;
    } else {
      const split = findYamlKeySeparator(rawValue);
      if (split >= 0 && !/^[{[]/.test(rawValue.trim())) {
        const childIndent = indent + 2;
        const firstKey = parseKey(rawValue.slice(0, split).trim(), line.line);
        const firstRaw = rawValue.slice(split + 1).trim();
        const object = {};
        object[firstKey] = firstRaw
          ? parseInlineValue(firstRaw, { syntax: 'yaml', line: line.line, limits: state.limits, depth: depth + 2, state })
          : (state.lines[state.index] && state.lines[state.index].indent > childIndent
            ? parseYamlBlock(state, state.lines[state.index].indent, depth + 2)
            : null);
        while (state.index < state.lines.length) {
          const next = state.lines[state.index];
          if (next.indent < childIndent) break;
          if (next.indent !== childIndent || /^-(?:\s|$)/.test(next.text)) break;
          const nextSplit = findYamlKeySeparator(next.text);
          if (nextSplit < 0) throw new ParseFailure('syntax-error', `Expected a mapping key at line ${next.line}`, next.line);
          const key = parseKey(next.text.slice(0, nextSplit).trim(), next.line);
          if (Object.hasOwn(object, key)) throw new ParseFailure('duplicate-key', `Duplicate YAML key "${key}" at line ${next.line}`, next.line);
          let nextRaw = next.text.slice(nextSplit + 1).trim();
          state.index += 1;
          const nextAnchor = takeAnchor(nextRaw);
          if (nextAnchor) nextRaw = nextAnchor.rest;
          let child;
          if (nextRaw === '|' || nextRaw === '>' || /^[|>][+-]?$/.test(nextRaw)) child = parseYamlBlockScalar(state, childIndent, nextRaw[0]);
          else if (!nextRaw) {
            const following = state.lines[state.index];
            child = following && following.indent > childIndent ? parseYamlBlock(state, following.indent, depth + 2) : null;
          } else child = parseInlineValue(nextRaw, { syntax: 'yaml', line: next.line, limits: state.limits, depth: depth + 2, state });
          object[key] = child;
          if (nextAnchor) state.anchors.set(nextAnchor.name, child);
        }
        value = object;
      } else value = parseInlineValue(rawValue, { syntax: 'yaml', line: line.line, limits: state.limits, depth: depth + 1, state });
    }
    countNode(state);
    result.push(value);
    if (anchor) state.anchors.set(anchor.name, value);
  }
  return result;
}

function parseYamlBlockScalar(state, parentIndent, style) {
  const collected = [];
  let minimumIndent = Infinity;
  let cursor = state.index;
  while (cursor < state.lines.length && state.lines[cursor].indent > parentIndent) {
    minimumIndent = Math.min(minimumIndent, state.lines[cursor].indent);
    cursor += 1;
  }
  while (state.index < cursor) {
    const line = state.lines[state.index++];
    collected.push(line.raw.slice(Math.min(minimumIndent, line.raw.length)));
  }
  const text = style === '>' ? foldYamlLines(collected) : collected.join('\n');
  return `${text}\n`;
}

function foldYamlLines(lines) {
  let result = '';
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line || !lines[index + 1]) result += `${line}\n`;
    else result += `${line} `;
  }
  return result.replace(/\n$/, '');
}

function resolveYamlAliases(root, state) {
  const resolvedAnchors = new Map();
  const resolving = new Set();

  const resolveAnchor = (name, depth) => {
    checkDepth(state, depth);
    if (!state.anchors.has(name)) throw new ParseFailure('unknown-alias', `Unknown YAML alias *${name}`);
    if (resolvedAnchors.has(name)) return deepClone(resolvedAnchors.get(name), state.limits);
    if (resolving.has(name)) throw new ParseFailure('alias-cycle', `YAML alias cycle involving *${name}`);
    resolving.add(name);
    const resolved = resolveNode(state.anchors.get(name), depth + 1);
    resolving.delete(name);
    resolvedAnchors.set(name, resolved);
    return deepClone(resolved, state.limits);
  };

  const resolveNode = (value, depth) => {
    checkDepth(state, depth);
    if (value instanceof AliasRef) return resolveAnchor(value.name, depth + 1);
    if (Array.isArray(value)) return value.map((item) => resolveNode(item, depth + 1));
    if (!isPlainObject(value)) return value;
    const result = {};
    let merges = [];
    for (const [key, child] of Object.entries(value)) {
      if (key === '<<') {
        const merged = resolveNode(child, depth + 1);
        merges = Array.isArray(merged) ? merged : [merged];
        continue;
      }
      result[key] = resolveNode(child, depth + 1);
    }
    for (const merged of merges) {
      if (!isPlainObject(merged)) throw new ParseFailure('syntax-error', 'YAML merge key must reference a mapping.');
      for (const [key, child] of Object.entries(merged)) if (!Object.hasOwn(result, key)) result[key] = deepClone(child, state.limits);
    }
    return result;
  };

  return resolveNode(root, 0);
}

function parseToml(content, limits) {
  const root = {};
  let current = root;
  const lines = String(content).replace(/^\uFEFF/, '').split(/\r?\n/);
  let nodes = 0;
  for (let index = 0; index < lines.length; index += 1) {
    let text = stripComment(lines[index]).trim();
    if (!text) continue;
    const lineNumber = index + 1;
    if (/^\[\[.*\]\]$/.test(text)) {
      const keys = parseDottedKey(text.slice(2, -2).trim(), lineNumber);
      current = appendArrayTable(root, keys, limits, lineNumber);
      continue;
    }
    if (/^\[.*\]$/.test(text)) {
      const keys = parseDottedKey(text.slice(1, -1).trim(), lineNumber);
      current = ensureObjectPath(root, keys, limits, lineNumber);
      continue;
    }
    const split = findTopLevelSeparator(text, '=');
    if (split < 0) throw new ParseFailure('syntax-error', `Expected TOML key/value assignment at line ${lineNumber}`, lineNumber);
    const keyParts = parseDottedKey(text.slice(0, split).trim(), lineNumber);
    let raw = text.slice(split + 1).trim();
    if (/^(?:"""|''')/.test(raw)) {
      const delimiter = raw.slice(0, 3);
      let body = raw.slice(3);
      let end = body.indexOf(delimiter);
      while (end < 0) {
        index += 1;
        if (index >= lines.length) throw new ParseFailure('syntax-error', `Unterminated TOML multiline string at line ${lineNumber}`, lineNumber);
        body += `\n${lines[index]}`;
        end = body.indexOf(delimiter);
        if (Buffer.byteLength(body) > limits.maxScalarBytes) throw new ParseFailure('scalar-limit', 'TOML multiline string exceeds maxScalarBytes.', lineNumber);
      }
      raw = `${delimiter}${body.slice(0, end)}${delimiter}`;
      const trailing = body.slice(end + 3).trim();
      if (trailing && !trailing.startsWith('#')) throw new ParseFailure('syntax-error', `Unexpected TOML text after multiline string at line ${index + 1}`, index + 1);
    }
    const value = parseInlineValue(raw, { syntax: 'toml', line: lineNumber, limits, depth: 1 });
    setPath(current, keyParts, value, limits, lineNumber);
    nodes += 1;
    if (nodes > limits.maxNodes) throw new ParseFailure('node-limit', 'TOML node limit exceeded.', lineNumber);
  }
  assertBounded(root, limits);
  return root;
}

function appendArrayTable(root, keys, limits, line) {
  if (!keys.length) throw new ParseFailure('syntax-error', 'Empty TOML array table.', line);
  const parent = resolveTomlPath(root, keys.slice(0, -1), limits, line);
  const key = keys.at(-1);
  if (!Object.hasOwn(parent, key)) parent[key] = [];
  if (!Array.isArray(parent[key])) throw new ParseFailure('duplicate-key', `TOML key ${keys.join('.')} already exists and is not an array.`, line);
  const object = {};
  parent[key].push(object);
  return object;
}

function ensureObjectPath(root, keys, limits, line) {
  return resolveTomlPath(root, keys, limits, line);
}

function resolveTomlPath(root, keys, limits, line) {
  let current = root;
  if (keys.length > limits.maxDepth) throw new ParseFailure('depth-limit', 'TOML table depth limit exceeded.', line);
  for (const key of keys) {
    if (Array.isArray(current)) {
      if (!current.length || !isPlainObject(current.at(-1))) throw new ParseFailure('syntax-error', `TOML array table ${key} has no current item.`, line);
      current = current.at(-1);
    }
    if (!isPlainObject(current)) throw new ParseFailure('duplicate-key', `TOML key ${key} is already assigned.`, line);
    if (!Object.hasOwn(current, key)) current[key] = {};
    const child = current[key];
    if (Array.isArray(child)) {
      if (!child.length || !isPlainObject(child.at(-1))) throw new ParseFailure('duplicate-key', `TOML key ${key} is already assigned.`, line);
      current = child.at(-1);
    } else if (isPlainObject(child)) current = child;
    else throw new ParseFailure('duplicate-key', `TOML key ${key} is already assigned.`, line);
  }
  return current;
}

function setPath(root, keys, value, limits, line) {
  if (!keys.length) throw new ParseFailure('syntax-error', 'Empty TOML key.', line);
  const parent = ensureObjectPath(root, keys.slice(0, -1), limits, line);
  const key = keys.at(-1);
  if (Object.hasOwn(parent, key)) throw new ParseFailure('duplicate-key', `Duplicate TOML key "${keys.join('.')}" at line ${line}`, line);
  parent[key] = value;
}

function parseInlineValue(text, context) {
  const parser = new InlineParser(String(text), context);
  const value = parser.parseValue(context.depth ?? 0);
  parser.skipWhitespace();
  if (!parser.eof()) throw new ParseFailure('syntax-error', `Unexpected token near "${parser.remaining().slice(0, 24)}"`, context.line);
  return value;
}

class InlineParser {
  constructor(text, context) {
    this.text = text;
    this.index = 0;
    this.context = context;
    this.nodes = 0;
  }

  eof() { return this.index >= this.text.length; }
  remaining() { return this.text.slice(this.index); }
  peek() { return this.text[this.index]; }
  skipWhitespace() { while (/\s/.test(this.peek() ?? '')) this.index += 1; }

  parseValue(depth) {
    if (depth > this.context.limits.maxDepth) throw new ParseFailure('depth-limit', 'Structured scalar depth limit exceeded.', this.context.line);
    this.skipWhitespace();
    this.nodes += 1;
    if (this.nodes > this.context.limits.maxNodes) throw new ParseFailure('node-limit', 'Structured node limit exceeded.', this.context.line);
    if (this.remaining().startsWith('"""') || this.remaining().startsWith("'''")) return this.parseMultilineString();
    const char = this.peek();
    if (char === '"' || char === "'") return this.parseQuotedString();
    if (char === '[') return this.parseArray(depth + 1);
    if (char === '{') return this.parseObject(depth + 1);
    if (char === '*' && this.context.syntax === 'yaml') {
      this.index += 1;
      const name = this.readIdentifier();
      const state = this.context.state;
      state.aliases += 1;
      if (state.aliases > state.limits.maxAliases) throw new ParseFailure('alias-limit', 'YAML alias limit exceeded.', this.context.line);
      return new AliasRef(name, this.context.line);
    }
    if (char === '!' && this.context.syntax === 'yaml') {
      this.index += 1;
      this.readIdentifier(/[A-Za-z0-9_:/.-]/);
      this.skipWhitespace();
      return this.parseValue(depth + 1);
    }
    if (char === '&' && this.context.syntax === 'yaml') {
      this.index += 1;
      const name = this.readIdentifier();
      this.skipWhitespace();
      const value = this.eof() ? null : this.parseValue(depth + 1);
      this.context.state.anchors.set(name, value);
      return value;
    }
    return this.parseBare();
  }

  parseQuotedString() {
    const quote = this.text[this.index++];
    let result = '';
    while (!this.eof()) {
      const char = this.text[this.index++];
      if (char === quote) return result;
      if (char === '\\' && quote === '"') {
        const next = this.text[this.index++];
        const escapes = { n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '"': '"', '\\': '\\', '/': '/' };
        if (next === 'u') {
          const hex = this.text.slice(this.index, this.index + 4);
          if (!/^[0-9a-f]{4}$/i.test(hex)) throw new ParseFailure('syntax-error', 'Invalid Unicode escape.', this.context.line);
          result += String.fromCodePoint(Number.parseInt(hex, 16));
          this.index += 4;
        } else result += escapes[next] ?? next;
      } else if (quote === "'" && char === "'" && this.peek() === "'") {
        result += "'";
        this.index += 1;
      } else result += char;
      if (Buffer.byteLength(result) > this.context.limits.maxScalarBytes) throw new ParseFailure('scalar-limit', 'Scalar exceeds maxScalarBytes.', this.context.line);
    }
    throw new ParseFailure('syntax-error', 'Unterminated quoted string.', this.context.line);
  }

  parseMultilineString() {
    const delimiter = this.text.slice(this.index, this.index + 3);
    this.index += 3;
    const end = this.text.indexOf(delimiter, this.index);
    if (end < 0) throw new ParseFailure('syntax-error', 'Unterminated multiline string.', this.context.line);
    const result = this.text.slice(this.index, end);
    this.index = end + 3;
    if (Buffer.byteLength(result) > this.context.limits.maxScalarBytes) throw new ParseFailure('scalar-limit', 'Scalar exceeds maxScalarBytes.', this.context.line);
    return result;
  }

  parseArray(depth) {
    this.index += 1;
    const result = [];
    while (true) {
      this.skipWhitespace();
      if (this.peek() === ']') { this.index += 1; return result; }
      result.push(this.parseValue(depth));
      this.skipWhitespace();
      if (this.peek() === ',') { this.index += 1; continue; }
      if (this.peek() === ']') { this.index += 1; return result; }
      throw new ParseFailure('syntax-error', 'Expected comma or closing bracket.', this.context.line);
    }
  }

  parseObject(depth) {
    this.index += 1;
    const result = {};
    while (true) {
      this.skipWhitespace();
      if (this.peek() === '}') { this.index += 1; return result; }
      const key = this.peek() === '"' || this.peek() === "'" ? this.parseQuotedString() : this.readUntilKeySeparator();
      this.skipWhitespace();
      const separator = this.peek();
      if (separator !== ':' && separator !== '=') throw new ParseFailure('syntax-error', 'Expected object key separator.', this.context.line);
      this.index += 1;
      if (Object.hasOwn(result, key)) throw new ParseFailure('duplicate-key', `Duplicate inline key "${key}".`, this.context.line);
      result[key] = this.parseValue(depth);
      this.skipWhitespace();
      if (this.peek() === ',') { this.index += 1; continue; }
      if (this.peek() === '}') { this.index += 1; return result; }
      throw new ParseFailure('syntax-error', 'Expected comma or closing brace.', this.context.line);
    }
  }

  parseBare() {
    const start = this.index;
    let quote = null;
    while (!this.eof()) {
      const char = this.peek();
      if (!quote && /[,\]}]/.test(char)) break;
      if (!quote && /\s/.test(char) && this.context.syntax === 'toml') break;
      if (char === '"' || char === "'") quote = quote === char ? null : (quote ?? char);
      this.index += 1;
    }
    const raw = this.text.slice(start, this.index).trim();
    if (!raw) throw new ParseFailure('syntax-error', 'Expected scalar value.', this.context.line);
    if (Buffer.byteLength(raw) > this.context.limits.maxScalarBytes) throw new ParseFailure('scalar-limit', 'Scalar exceeds maxScalarBytes.', this.context.line);
    if (/^(?:null|~)$/i.test(raw)) return null;
    if (/^(?:true|false)$/i.test(raw)) return raw.toLowerCase() === 'true';
    if (/^[+-]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?(?:[eE][+-]?[0-9_]+)?$/.test(raw)) return Number(raw.replaceAll('_', ''));
    if (/^[+-]?(?:inf|nan)$/i.test(raw)) return raw.toLowerCase().includes('nan') ? Number.NaN : (raw.startsWith('-') ? -Infinity : Infinity);
    if (this.context.syntax === 'toml' && /^\d{4}-\d{2}-\d{2}(?:[Tt ][0-9:.+-]+[Zz]?)?$/.test(raw)) return raw;
    return raw;
  }

  readIdentifier(pattern = /[A-Za-z0-9_.-]/) {
    const start = this.index;
    while (!this.eof() && pattern.test(this.peek())) this.index += 1;
    const value = this.text.slice(start, this.index);
    if (!value) throw new ParseFailure('syntax-error', 'Expected identifier.', this.context.line);
    return value;
  }

  readUntilKeySeparator() {
    const start = this.index;
    while (!this.eof() && this.peek() !== ':' && this.peek() !== '=') this.index += 1;
    const value = this.text.slice(start, this.index).trim();
    if (!value) throw new ParseFailure('syntax-error', 'Expected object key.', this.context.line);
    return value;
  }
}

function assertBounded(root, limits) {
  const stack = [{ value: root, depth: 0 }];
  const seen = new WeakSet();
  let nodes = 0;
  while (stack.length) {
    const { value, depth } = stack.pop();
    if (depth > limits.maxDepth) throw new ParseFailure('depth-limit', 'Structured config depth limit exceeded.');
    nodes += 1;
    if (nodes > limits.maxNodes) throw new ParseFailure('node-limit', 'Structured config node limit exceeded.');
    if (typeof value === 'string' && Buffer.byteLength(value) > limits.maxScalarBytes) throw new ParseFailure('scalar-limit', 'Structured scalar exceeds maxScalarBytes.');
    if (!value || typeof value !== 'object') continue;
    if (seen.has(value)) throw new ParseFailure('alias-cycle', 'Structured config contains a cyclic object graph.');
    seen.add(value);
    for (const child of Array.isArray(value) ? value : Object.values(value)) stack.push({ value: child, depth: depth + 1 });
  }
}

function deepClone(value, limits) {
  const clone = structuredClone(value);
  assertBounded(clone, limits);
  return clone;
}

function findYamlKeySeparator(text) {
  let quote = null;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (char === '\\' && quote === '"') index += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") { quote = char; continue; }
    if (char === '[') square += 1;
    else if (char === ']') square -= 1;
    else if (char === '{') curly += 1;
    else if (char === '}') curly -= 1;
    else if (char === ':' && square === 0 && curly === 0 && (index + 1 === text.length || /\s/.test(text[index + 1]))) return index;
  }
  return -1;
}

function findTopLevelSeparator(text, separator) {
  let quote = null;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (char === '\\' && quote === '"') index += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === '[') square += 1;
    else if (char === ']') square -= 1;
    else if (char === '{') curly += 1;
    else if (char === '}') curly -= 1;
    else if (char === separator && square === 0 && curly === 0) return index;
  }
  return -1;
}

function stripComment(text) {
  let quote = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (char === '\\' && quote === '"') index += 1;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'") quote = char;
    else if (char === '#') return text.slice(0, index);
  }
  return text;
}

function parseDottedKey(text, line) {
  const parts = [];
  let current = '';
  let quote = null;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote) {
      if (char === '\\' && quote === '"') current += text[++index] ?? '';
      else if (char === quote) quote = null;
      else current += char;
    } else if (char === '"' || char === "'") quote = char;
    else if (char === '.') {
      if (!current.trim()) throw new ParseFailure('syntax-error', `Invalid dotted TOML key at line ${line}`, line);
      parts.push(current.trim());
      current = '';
    } else current += char;
  }
  if (quote) throw new ParseFailure('syntax-error', `Unterminated TOML key at line ${line}`, line);
  if (!current.trim()) throw new ParseFailure('syntax-error', `Invalid TOML key at line ${line}`, line);
  parts.push(current.trim());
  return parts;
}

function parseKey(text, line) {
  if (!text) throw new ParseFailure('syntax-error', `Empty mapping key at line ${line}`, line);
  if ((text.startsWith('"') && text.endsWith('"')) || (text.startsWith("'") && text.endsWith("'"))) {
    return text.slice(1, -1);
  }
  return text;
}

function takeAnchor(text) {
  const match = /^&([A-Za-z0-9_.-]+)(?:\s+(.*))?$/.exec(text);
  return match ? { name: match[1], rest: match[2] ?? '' } : null;
}

function countNode(state) {
  state.nodes += 1;
  if (state.nodes > state.limits.maxNodes) throw new ParseFailure('node-limit', 'YAML node limit exceeded.');
}

function checkDepth(state, depth) {
  if (depth > state.limits.maxDepth) throw new ParseFailure('depth-limit', 'Structured config depth limit exceeded.');
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value) && !(value instanceof AliasRef);
}
