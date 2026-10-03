import test from 'node:test';
import assert from 'node:assert/strict';
import { scanEdgeAbuseShield } from '../src/edge-abuse-shield.mjs';

const ids = (file, source) => new Set(scanEdgeAbuseShield(file, source).map(f => f.id));

test('flags a high-value POST route with no observable abuse guard', () => {
  const source = `export async function POST(req) {
  const body = await req.json();
  return login(body.email, body.password);
}`;
  assert(ids('src/app/api/auth/login/route.ts', source).has('high-value-route-no-abuse-guard'));
});

test('does not flag an auth POST route when a rate limiter or challenge is present', () => {
  const source = `import { Ratelimit } from "@upstash/ratelimit";
const limiter = new Ratelimit({ redis });
export async function POST(req) {
  const result = await limiter.limit("login");
  if (!result.success) return new Response("Too Many Requests", { status: 429 });
  return new Response("ok");
}`;
  assert(!ids('src/app/api/auth/login/route.ts', source).has('high-value-route-no-abuse-guard'));
});

test('flags rate limits keyed from X-Forwarded-For without a trusted proxy boundary', () => {
  const source = `const limiter = rateLimit({ max: 10 });
export async function POST(req) {
  const ip = req.headers.get("x-forwarded-for");
  return limiter.limit(ip);
}`;
  assert(ids('src/app/api/login/route.ts', source).has('spoofable-forwarded-ip-rate-limit'));
});

test('flags in-memory rate-limit state on a high-value route', () => {
  const source = `const attempts = new Map();
export async function POST(req) {
  const key = "login";
  const count = attempts.get(key) || 0;
  if (count > 5) return new Response("Too Many Requests", { status: 429 });
  attempts.set(key, count + 1);
  return new Response("ok");
}`;
  assert(ids('src/app/api/login/route.ts', source).has('serverless-in-memory-rate-limit'));
});

test('flags bot verification secrets referenced from client code', () => {
  const source = `"use client";
const secret = process.env.TURNSTILE_SECRET_TOKEN;
export function Form() { return <form />; }`;
  assert(ids('src/components/login-form.tsx', source).has('client-bot-secret-reference'));
});
