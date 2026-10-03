import test from 'node:test';
import assert from 'node:assert/strict';
import { scanWebThreatIntel } from '../src/web-threat-intel.mjs';

test('flags Next.js 16.2.10 for current 2026 security advisories', () => {
  const content = JSON.stringify({
    dependencies: { next: '16.2.10', react: '19.2.4' }
  }, null, 2);
  const ids = new Set(scanWebThreatIntel('package.json', content).map(f => f.id));
  assert(ids.has('nextjs-image-response-rce-version'));
  assert(ids.has('nextjs-avif-image-optimization-rce-version'));
  assert(ids.has('nextjs-july-2026-security-cluster'));
});

test('does not flag patched Next.js 16.3.6 for those version ranges', () => {
  const content = JSON.stringify({ dependencies: { next: '16.3.6' } }, null, 2);
  const ids = new Set(scanWebThreatIntel('package.json', content).map(f => f.id));
  assert(!ids.has('nextjs-image-response-rce-version'));
  assert(!ids.has('nextjs-avif-image-optimization-rce-version'));
  assert(!ids.has('nextjs-july-2026-security-cluster'));
});

test('flags request-controlled SVG passed to Node ImageResponse', () => {
  const source = `import { ImageResponse } from "next/og";
export async function GET(request) {
  const value = new URL(request.url).searchParams.get("value") || "";
  return new ImageResponse(<svg><title>{value}</title></svg>);
}`;
  const ids = new Set(scanWebThreatIntel('src/app/og/route.tsx', source).map(f => f.id));
  assert(ids.has('nextjs-image-response-untrusted-svg'));
});

test('does not flag the ImageResponse source heuristic when explicitly using Edge runtime', () => {
  const source = `import { ImageResponse } from "next/og";
export const runtime = "edge";
export async function GET(request) {
  const value = new URL(request.url).searchParams.get("value") || "";
  return new ImageResponse(<svg><title>{value}</title></svg>);
}`;
  const ids = new Set(scanWebThreatIntel('src/app/og/route.tsx', source).map(f => f.id));
  assert(!ids.has('nextjs-image-response-untrusted-svg'));
});

test('flags dynamic external rewrite hostnames', () => {
  const source = `export default {
    async rewrites() {
      return [{ source: "/:tenant", destination: "https://:tenant.api.example.com" }];
    }
  };`;
  const ids = new Set(scanWebThreatIntel('next.config.ts', source).map(f => f.id));
  assert(ids.has('nextjs-dynamic-rewrite-host-ssrf'));
});
