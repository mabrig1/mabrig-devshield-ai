// Offline Portable Executable (PE32/PE32+) inspection. No execution, emulation,
// unpacking, API calls, signature trust evaluation or third-party file uploads.
// Findings are static triage indicators, not diagnoses or malware verdicts.
const MAX_SECTIONS = 96;
const MAX_IMPORT_DESCRIPTORS = 128;
const MAX_THUNKS = 2048;
const EXECUTE = 0x20000000;
const WRITE = 0x80000000;
const MAX_ENTROPY_SAMPLE = 256 * 1024;

const HIGH_RISK_APIS = new Set([
  'virtualallocex', 'writeprocessmemory', 'createremotethread',
  'ntcreatethreadex', 'rtlcreateuserthread', 'queueuserapc',
  'ntqueueapcthread', 'virtualprotectex', 'setwindowshookexw',
  'setwindowshookexa', 'ntunmapviewofsection'
]);
const REMOTE_MEMORY = new Set(['virtualallocex', 'writeprocessmemory', 'virtualprotectex']);
const REMOTE_THREAD = new Set(['createremotethread', 'ntcreatethreadex',
  'rtlcreateuserthread', 'queueuserapc', 'ntqueueapcthread']);
const NETWORK_APIS = new Set(['urldownloadtofilea', 'urldownloadtofilew',
  'internetopenurla', 'internetopenurlw', 'winhttpconnect',
  'winhttpsendrequest', 'wsaconnect', 'connect']);

function within(bytes, offset, size = 1) {
  return Number.isSafeInteger(offset) && Number.isSafeInteger(size) &&
    offset >= 0 && size >= 0 && offset <= bytes.length && size <= bytes.length - offset;
}
function requireBytes(bytes, offset, size, name) {
  if (!within(bytes, offset, size)) throw Error('Truncated or malformed ' + name);
}
function u16(bytes, at, name = 'PE header') {
  requireBytes(bytes, at, 2, name);
  return bytes.readUInt16LE(at);
}
function u32(bytes, at, name = 'PE header') {
  requireBytes(bytes, at, 4, name);
  return bytes.readUInt32LE(at);
}
function ascii(bytes, at, maxLen, name) {
  requireBytes(bytes, at, 1, name);
  const limit = Math.min(bytes.length, at + maxLen + 1);
  const nul = bytes.indexOf(0, at);
  if (nul < at || nul >= limit) throw Error('Unterminated or oversized ' + name);
  const value = bytes.toString('latin1', at, nul);
  if (!/^[\x20-\x7e]+$/.test(value)) throw Error('Invalid ASCII in ' + name);
  return value;
}
function entropy(bytes, offset, size) {
  const len = Math.min(size, MAX_ENTROPY_SAMPLE);
  if (len < 2048) return null;
  const counts = new Uint32Array(256);
  for (let i = 0; i < len; i++) counts[bytes[offset + i]]++;
  let shannon = 0;
  for (const count of counts) {
    if (!count) continue;
    const p = count / len;
    shannon -= p * Math.log2(p);
  }
  return Number(shannon.toFixed(2));
}
function signal(rule, severity, message, remediation) {
  return { rule, severity, message, remediation, category: 'executable-heuristics' };
}

export function inspectPortableExecutable(bytes) {
  if (!Buffer.isBuffer(bytes)) throw TypeError('Expected a bounded file Buffer');
  requireBytes(bytes, 0, 64, 'DOS header');
  if (bytes.toString('ascii', 0, 2) !== 'MZ') throw Error('Not an MZ executable');
  const nt = u32(bytes, 0x3c, 'DOS e_lfanew');
  if (nt < 64 || nt > bytes.length - 24) throw Error('PE header offset outside file');
  requireBytes(bytes, nt, 24, 'NT headers');
  if (bytes.toString('latin1', nt, nt + 4) !== 'PE\u0000\u0000') {
    throw Error('MZ image lacks PE signature');
  }
  const machine = u16(bytes, nt + 4);
  const count = u16(bytes, nt + 6);
  const optionalSize = u16(bytes, nt + 20);
  if (!count || count > MAX_SECTIONS) throw Error('Invalid PE section count');
  const optional = nt + 24;
  requireBytes(bytes, optional, optionalSize, 'optional header');
  const magic = u16(bytes, optional);
  if (magic !== 0x10b && magic !== 0x20b) throw Error('Unsupported PE optional-header format');
  const pe64 = magic === 0x20b;
  const dataDirs = pe64 ? 112 : 96;
  if (optionalSize < dataDirs) throw Error('Truncated PE optional header');
  const countDirectories = u32(bytes, optional + (pe64 ? 108 : 92));
  const imageSize = u32(bytes, optional + 56);
  const sizeHeaders = u32(bytes, optional + 60);
  const sectionTable = optional + optionalSize;
  requireBytes(bytes, sectionTable, count * 40, 'section table');
  const sections = [];
  let writableExecutable = 0;
  let highEntropyExecutable = 0;
  for (let i = 0; i < count; i++) {
    const at = sectionTable + i * 40;
    const nameBytes = bytes.subarray(at, at + 8);
    const nul = nameBytes.indexOf(0);
    const rawName = nameBytes.toString('latin1', 0, nul < 0 ? 8 : nul);
    const name = /^[\x20-\x7e]*$/.test(rawName) ? rawName : 'non-ascii';
    const virtualSize = u32(bytes, at + 8);
    const virtualAddress = u32(bytes, at + 12);
    const rawSize = u32(bytes, at + 16);
    const rawOffset = u32(bytes, at + 20);
    const characteristics = u32(bytes, at + 36);
    if (rawSize && !within(bytes, rawOffset, rawSize)) {
      throw Error('PE section data extends beyond file');
    }
    const executable = !!(characteristics & EXECUTE);
    const writable = !!(characteristics & WRITE);
    const sectionEntropy = rawSize ? entropy(bytes, rawOffset, rawSize) : null;
    if (executable && writable) writableExecutable++;
    if (executable && sectionEntropy !== null && sectionEntropy >= 7.6) {
      highEntropyExecutable++;
    }
    sections.push({ name, virtualAddress, virtualSize, rawSize, rawOffset,
      executable, writable, entropy: sectionEntropy });
  }
  function rvaToOffset(rva, size = 1) {
    if (!rva) throw Error('Missing RVA');
    if (rva < sizeHeaders && within(bytes, rva, size)) return rva;
    for (const section of sections) {
      const delta = rva - section.virtualAddress;
      if (delta >= 0 && delta < Math.max(section.rawSize, section.virtualSize) &&
          delta + size <= section.rawSize) {
        const off = section.rawOffset + delta;
        if (within(bytes, off, size)) return off;
      }
    }
    throw Error('Import RVA outside backed file data');
  }
  const foundApis = new Set();
  let libraries = 0;
  let apiCount = 0;
  if (countDirectories >= 2) {
    if (optionalSize < dataDirs + 16) throw Error('Truncated PE import directory metadata');
    const importRva = u32(bytes, optional + dataDirs + 8);
    const importSize = u32(bytes, optional + dataDirs + 12);
    if (importRva && importSize) {
      const dir = rvaToOffset(importRva, 20);
      let done = false;
      for (let i = 0; i < MAX_IMPORT_DESCRIPTORS; i++) {
        const at = dir + i * 20;
        requireBytes(bytes, at, 20, 'import directory');
        const lookupRva = u32(bytes, at);
        const nameRva = u32(bytes, at + 12);
        const addressRva = u32(bytes, at + 16);
        if (!lookupRva && !nameRva && !addressRva) { done = true; break; }
        if (!nameRva || !(lookupRva || addressRva)) throw Error('Malformed import descriptor');
        const dllName = ascii(bytes, rvaToOffset(nameRva), 150, 'imported DLL').toLowerCase();
        if (!/\.(?:dll|ocx|sys)$/.test(dllName)) throw Error('Invalid imported module name');
        libraries++;
        const thunkRva = lookupRva || addressRva;
        let terminated = false;
        const width = pe64 ? 8 : 4;
        for (let k = 0; k < MAX_THUNKS; k++) {
          const thunkAt = rvaToOffset(thunkRva + k * width, width);
          const thunk = pe64 ? bytes.readBigUInt64LE(thunkAt) : BigInt(u32(bytes, thunkAt));
          if (thunk === 0n) { terminated = true; break; }
          apiCount++;
          const ordinal = pe64 ? (thunk & 0x8000000000000000n) : (thunk & 0x80000000n);
          if (ordinal) continue;
          if (thunk > 0xffffffffn) throw Error('Invalid import name RVA');
          const hintName = rvaToOffset(Number(thunk), 3);
          const api = ascii(bytes, hintName + 2, 150, 'imported function').toLowerCase();
          if (HIGH_RISK_APIS.has(api) || NETWORK_APIS.has(api)) foundApis.add(api);
        }
        if (!terminated) throw Error('Unterminated import thunk array');
      }
      if (!done) throw Error('Unterminated PE import directory');
    } else if (importRva || importSize) {
      throw Error('Incomplete PE import directory');
    }
  }
  const apis = [...foundApis].sort();
  const findings = [];
  if (writableExecutable) findings.push(signal('pe-writable-executable-section', 'medium',
    'The PE contains a section with writable and executable permissions.',
    'Review whether this is an expected JIT/packer behavior; compare against trusted builds.'));
  if (highEntropyExecutable) findings.push(signal('pe-high-entropy-code', 'medium',
    'The PE contains a highly entropic executable section (possible compression or packing).',
    'Compare with the software vendor and inspect the binary in a sandbox if needed.'));
  if (apis.some(api => REMOTE_MEMORY.has(api)) && apis.some(api => REMOTE_THREAD.has(api))) {
    findings.push(signal('pe-remote-process-injection-apis', 'high',
      'The import table combines remote-process memory APIs with remote thread/APC APIs.',
      'Investigate legitimate debugging/JIT use and verify publisher and expected behavior.'));
  }
  // Search a bounded collection of plain and UTF-16LE string indicators. Presence
  // does not prove execution; never decode or execute embedded commands.
  const latin = bytes.toString('latin1');
  const utf16 = bytes.toString('utf16le');
  const encodedCommand = /\b(?:powershell|pwsh)(?:\.exe)?[\s\S]{0,80}-(?:enc|encodedcommand)\b/i;
  if (encodedCommand.test(latin) || encodedCommand.test(utf16)) {
    findings.push(signal('pe-embedded-encoded-powershell', 'high',
      'Executable contains a PowerShell encoded-command string indicator.',
      'Do not execute. Confirm provenance and analyze embedded commands in an isolated lab.'));
  }
  const network = apis.some(api => NETWORK_APIS.has(api));
  if (network && apis.some(api => REMOTE_THREAD.has(api)) && !findings.some(f => f.rule === 'pe-remote-process-injection-apis')) {
    findings.push(signal('pe-network-and-remote-thread-apis', 'medium',
      'Executable imports network and remote-thread-related functions.',
      'Investigate the intended network and process-management behavior.'));
  }
  return {
    format: pe64 ? 'PE32+' : 'PE32',
    machine: '0x' + machine.toString(16),
    imageSize,
    sectionCount: count,
    importLibraryCount: libraries,
    importFunctionCount: apiCount,
    suspiciousImportNames: apis.slice(0, 32),
    writableExecutableSections: writableExecutable,
    highEntropyExecutableSections: highEntropyExecutable,
    findings
  };
}
