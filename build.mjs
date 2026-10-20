#!/usr/bin/env node
// MEP,SFA — PINロック付きページのビルドスクリプト
//
//   PIN=12345678 node build.mjs encrypt   … src/app.html を暗号化して index.html を作る
//   PIN=12345678 node build.mjs decrypt   … index.html を復号して src/app.html を取り出す
//
//   DOCS_PIN=0001 を一緒に指定すると、資料ダウンロードの一覧（/*DOCS:PLAIN*/…/*DOCS:PLAIN_END*/）を
//   さらにそのコードで暗号化します（decrypt 時も DOCS_PIN があれば平文に戻します）。
//
// src/app.html（平文の中身）は .gitignore で除外しており、リポジトリには
// 暗号化済みの index.html だけが載ります。編集するときは decrypt → 編集 → encrypt。

import { webcrypto as crypto } from 'node:crypto';
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(fileURLToPath(import.meta.url));
const SRC = join(ROOT, 'src', 'app.html');
const OUT = join(ROOT, 'index.html');
const TEMPLATE = join(ROOT, 'lock-template.html');
const ITERATIONS = 600000;

const mode = process.argv[2];
const pin = process.env.PIN;
if (!['encrypt', 'decrypt'].includes(mode)) {
  console.error('使い方: PIN=xxxx node build.mjs encrypt|decrypt');
  process.exit(1);
}
if (!pin || !/^\d{4,12}$/.test(pin)) {
  console.error('環境変数 PIN に 4〜12桁の数字を指定してください');
  process.exit(1);
}

const enc = new TextEncoder();
const b64 = (u8) => Buffer.from(u8).toString('base64');
const unb64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));

async function deriveKey(salt, code = pin) {
  const base = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

const docsPin = process.env.DOCS_PIN;
const DOCS_RE = /\/\*DOCS:PLAIN\*\/([\s\S]*?)\/\*DOCS:PLAIN_END\*\//;
const DOCS_ENC_RE = /\/\*DOCS:ENC\*\/([\s\S]*?)\/\*DOCS:ENC_END\*\//;
async function lockDocs(html) {
  const m = html.match(DOCS_RE);
  if (!m) return html;
  if (!docsPin) { console.error('資料一覧が平文です。DOCS_PIN=コード を指定してください'); process.exit(1); }
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt, docsPin);
  const plain = JSON.stringify(JSON.parse(m[1].replace(/,\s*\]$/, ']')));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
  const blob = JSON.stringify({ v: 1, it: ITERATIONS, s: b64(salt), i: b64(iv), c: b64(ct) });
  return html.replace(DOCS_RE, () => '/*DOCS:ENC*/' + blob + '/*DOCS:ENC_END*/');
}
async function unlockDocs(html) {
  const m = html.match(DOCS_ENC_RE);
  if (!m || !docsPin) return html;
  const p = JSON.parse(m[1]);
  const key = await deriveKey(unb64(p.s), docsPin);
  const pt = Buffer.from(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(p.i) }, key, unb64(p.c))).toString('utf8');
  return html.replace(DOCS_ENC_RE, () => '/*DOCS:PLAIN*/' + JSON.stringify(JSON.parse(pt), null, 2) + '/*DOCS:PLAIN_END*/');
}

if (mode === 'encrypt') {
  const html = await lockDocs(readFileSync(SRC, 'utf8'));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(html)));
  const payload = JSON.stringify({ v: 1, it: ITERATIONS, s: b64(salt), i: b64(iv), c: b64(ct) });
  const tpl = readFileSync(TEMPLATE, 'utf8');
  if (!tpl.includes('/*__PAYLOAD__*/null')) throw new Error('テンプレートに埋め込み位置がありません');
  writeFileSync(OUT, tpl.replace('/*__PAYLOAD__*/null', payload));
  console.log(`暗号化しました → index.html（${(ct.length / 1024).toFixed(1)} KB）`);
} else {
  const page = readFileSync(OUT, 'utf8');
  const m = page.match(/const PAYLOAD = (\{.*?\});/s);
  if (!m) throw new Error('index.html に暗号データが見つかりません');
  const p = JSON.parse(m[1]);
  const key = await deriveKey(unb64(p.s));
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(p.i) }, key, unb64(p.c));
  } catch {
    console.error('PINが違います');
    process.exit(1);
  }
  mkdirSync(dirname(SRC), { recursive: true });
  writeFileSync(SRC, await unlockDocs(Buffer.from(pt).toString('utf8')));
  console.log('復号しました → src/app.html');
}
