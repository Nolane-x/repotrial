import { generateKeyPair, sign, verify, createPublicKey } from 'node:crypto';
import { promisify } from 'node:util';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { sha256, stableStringify } from '../core/hash.mjs';

const generate = promisify(generateKeyPair);
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';

export async function generateSigningKeyPair(directory, options = {}) {
  const output = path.resolve(directory);
  await mkdir(output, { recursive: true });
  const { publicKey, privateKey } = await generate('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem', ...(options.passphrase ? { cipher: 'aes-256-cbc', passphrase: options.passphrase } : {}) }
  });
  const privatePath = path.join(output, options.privateName ?? 'repotrial-signing-key.pem');
  const publicPath = path.join(output, options.publicName ?? 'repotrial-signing-key.pub.pem');
  await writeFile(privatePath, privateKey, { mode: 0o600 });
  await writeFile(publicPath, publicKey, { mode: 0o644 });
  return { privateKey: privatePath, publicKey: publicPath, keyId: keyId(publicKey) };
}

export async function signStatement(statement, privateKeyInput, options = {}) {
  const privateKey = await readKey(privateKeyInput);
  const payload = Buffer.from(stableStringify(statement));
  const signature = sign(null, pae(PAYLOAD_TYPE, payload), { key: privateKey, ...(options.passphrase ? { passphrase: options.passphrase } : {}) });
  const publicKey = createPublicKey({ key: privateKey, ...(options.passphrase ? { passphrase: options.passphrase } : {}) }).export({ type: 'spki', format: 'pem' });
  return {
    payloadType: PAYLOAD_TYPE,
    payload: payload.toString('base64'),
    signatures: [{ keyid: keyId(publicKey), sig: signature.toString('base64') }]
  };
}

export async function verifyEnvelope(envelope, publicKeyInput) {
  try {
    if (!envelope || envelope.payloadType !== PAYLOAD_TYPE || typeof envelope.payload !== 'string' || !Array.isArray(envelope.signatures)) return { valid: false, error: 'invalid-envelope' };
    const publicKey = await readKey(publicKeyInput);
    const payload = Buffer.from(envelope.payload, 'base64');
    const matchingId = keyId(createPublicKey(publicKey).export({ type: 'spki', format: 'pem' }));
    const valid = envelope.signatures.some((entry) => entry?.keyid === matchingId && verify(null, pae(envelope.payloadType, payload), publicKey, Buffer.from(entry.sig, 'base64')));
    let statement = null;
    try { statement = JSON.parse(payload.toString('utf8')); } catch { return { valid: false, error: 'invalid-payload-json' }; }
    return { valid, statement, keyId: matchingId, ...(valid ? {} : { error: 'signature-mismatch' }) };
  } catch (error) {
    return { valid: false, error: error instanceof Error ? error.message : String(error) };
  }
}

export function pae(payloadType, payload) {
  const type = Buffer.from(payloadType);
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([Buffer.from(`DSSEv1 ${type.length} `), type, Buffer.from(` ${data.length} `), data]);
}

async function readKey(input) {
  if (Buffer.isBuffer(input)) return input;
  const text = String(input);
  if (text.includes('-----BEGIN')) return text;
  return readFile(path.resolve(text), 'utf8');
}
function keyId(publicKey) { return `sha256:${sha256(Buffer.from(String(publicKey)))}`; }
