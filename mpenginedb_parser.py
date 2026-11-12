#!/usr/bin/env python3
"""
mpenginedb_parser.py
Forensic parser for Microsoft Defender MpEngineDb ("MetaVault"):
  C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\mpenginedb.db (+ -wal)

What it does
  1. Hashes the evidence (MD5, SHA-1, SHA-256) before and after. Inputs are only read.
  2. Detects the page protection. Defender encrypts every page with RC4 using a fixed
     256-byte key from mpengine.dll. Known keys are tried first, then the key is
     recovered from the file itself, so unknown engine builds still work.
  3. Decrypts the database and the WAL, validates the WAL checksum chain exactly as
     SQLite does, and rebuilds the database at every WAL commit.
  4. Decodes every field (FILETIME, NTFS file reference, volume serial, GUIDs, hashes,
     ssdeep, JSON, pid/process start) and labels values with MITRE ATT&CK, the ASR
     rule list and a catalogue of values written by Defender signatures.
  5. Recovers deleted rows: rows removed between WAL commits, plus records carved from
     free pages, freeblocks, unallocated space, uncommitted and stale WAL frames.
  6. Writes CSV per table, a merged timeline, recovered rows, row history, a summary,
     a run log and a SHA-256 manifest of every output file.

Usage
  python3 mpenginedb_parser.py -f <mpenginedb.db | folder> [--wal <file>] -o <outdir>
         [--keep-states] [--no-carve] [--all-tables]

Python 3.8+, standard library only. Optional lookup files are read from ./lookups
next to this script (mitre_attack.json, asr_rules.json, vdm_catalog.json).
"""
import argparse, collections, csv, datetime, hashlib, json, logging, os, re, sqlite3, struct, sys, time

TOOL = 'mpenginedb_parser'
VERSION = '1.0.5'
PS_DEFAULT = 4096
MAGIC = b'SQLite format 3\x00'

# RC4 keys found in mpengine.dll builds (offset of the 256-byte array noted for reference)
KNOWN_KEYS = {
    '1.1.26100.4 (RVA 0xE31A10)': bytes.fromhex(
        '1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54fa'
        'a21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cbce48e23d053'
        '71ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe'
        '3c8a775233557dde13a8b14087cc1bc8f10f6ecdd083a959cff84a9d1d50755e'
        '3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd029'
        '1771861a54b4c285a9a3db7aca6d224aeacd621db9f2a22ed1e9e11d75bed7dc'
        '0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429b'
        'a495676b8398db2f35d3c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253'),
}

log = logging.getLogger(TOOL)

# --------------------------------------------------------------------------- helpers

def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def file_hashes(path):
    h = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            for x in h: x.update(chunk)
    return {'md5': h[0].hexdigest(), 'sha1': h[1].hexdigest(), 'sha256': h[2].hexdigest(),
            'size': os.path.getsize(path)}

def rc4_stream(key, n):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 255; S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray(n)
    for k in range(n):
        i = (i + 1) & 255; j = (j + S[i]) & 255; S[i], S[j] = S[j], S[i]
        out[k] = S[(S[i] + S[j]) & 255]
    return bytes(out)

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

EPOCH = datetime.datetime(1601, 1, 1)
FT_MIN, FT_MAX = 119600064000000000, 159793632000000000   # 1980-01-01 .. 2107-01-01

def ft_ok(v):
    return isinstance(v, int) and FT_MIN <= v < FT_MAX

def ft_str(v):
    if not ft_ok(v): return ''
    dt = EPOCH + datetime.timedelta(microseconds=v // 10)
    return dt.strftime('%Y-%m-%d %H:%M:%S.') + '%07d' % (v % 10_000_000)

def guid_le(b):
    if not isinstance(b, (bytes, bytearray)) or len(b) != 16: return ''
    d1, d2, d3 = struct.unpack('<IHH', b[:8])
    return '%08x-%04x-%04x-%s-%s' % (d1, d2, d3, b[8:10].hex(), b[10:].hex())

# --------------------------------------------------------------------------- lookups

class Lookups:
    def __init__(self, base):
        self.mitre, self.asr, self.cat, self.meta = {}, {}, {}, {}
        self.vulns = {}
        for name, attr, key in (('mitre_attack.json', 'mitre', 'techniques'),
                                ('asr_rules.json', 'asr', 'rules'),
                                ('vdm_catalog.json', 'cat', 'values')):
            p = os.path.join(base, name)
            if os.path.exists(p):
                d = json.load(open(p, encoding='utf-8'))
                setattr(self, attr, d.get(key, {})); self.meta[name] = d.get('meta', {})
                log.info('lookup %s loaded (%d entries)', name, len(d.get(key, {})))
            else:
                log.warning('lookup %s not found, values will not be labelled', name)

    def technique(self, t):
        t = (t or '').strip(); base = t.split(':')[0].strip()
        e = self.mitre.get(base)
        if not e: return ''
        s = e['name']
        if e.get('status') == 'revoked': s += ' [revoked, now %s]' % e.get('replaced_by', '?')
        elif e.get('status') == 'deprecated': s += ' [deprecated]'
        return s

    def asr_name(self, g):
        g = (g or '').lower()
        if not g: return ''
        return self.asr.get(g, 'not in Microsoft published ASR list (undocumented or preview rule)')

    def label(self, v):
        if not isinstance(v, str) or not v: return ''
        parts = []
        t = self.technique(v) if re.match(r'^T\d{4}', v) else ''
        if t: parts.append('ATT&CK ' + v.split(':')[0] + ' ' + t)
        e = self.cat.get(v)
        if e: parts.append('%s (Defender signature helper %s)' % (e['category'], '/'.join(e['apis'][:2])))
        for g in re.findall(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', v):
            parts.append('ASR ' + self.asr_name(g))
        return '; '.join(parts)

# --------------------------------------------------------------------------- crypto layer

class Codec:
    """Defender MetaVault page codec: RC4(fixed key), restarted for every call.
    Page 1: bytes 0-15 and 24-end transformed separately, 16-23 in clear."""
    def __init__(self, keystream, ps):
        self.ks, self.ps = keystream, ps

    def page(self, data, pgno):
        if pgno != 1: return xor(data, self.ks)
        return xor(data[:16], self.ks[:16]) + data[16:24] + xor(data[24:], self.ks[:self.ps - 24])

def derive_keystream(pages, frames, ps):
    """Recover the keystream from the file: known header plaintext + zero-filled free space."""
    allp = pages + frames
    key = bytearray(collections.Counter(p[i] for p in allp).most_common(1)[0][0] for i in range(ps))
    kp = xor(pages[0][:16], MAGIC); key[:16] = kp
    nonroot = pages[1:] + frames

    def gap(p):
        best, s = (0, 0, 0), None
        for i in range(8, ps + 1):
            m = i < ps and p[i] == key[i]
            if m and s is None: s = i
            if not m and s is not None:
                if i - s > best[0]: best = (i - s, s, i)
                s = None
        return best
    v56, v34 = collections.Counter(), collections.Counter()
    for p in nonroot:
        t = p[0] ^ key[0]
        if t not in (2, 5, 10, 13): continue
        L, gs, ge = gap(p)
        if L < 16: continue
        hl = 12 if t in (2, 5) else 8
        v56[(p[5] ^ ((ge >> 8) & 255), p[6] ^ (ge & 255))] += 1
        if (gs - hl) % 2 == 0:
            n = (gs - hl) // 2; v34[(p[3] ^ (n >> 8), p[4] ^ (n & 255))] += 1
    if v56: key[5], key[6] = v56.most_common(1)[0][0]
    if v34: key[3], key[4] = v34.most_common(1)[0][0]
    votes = [collections.Counter() for _ in range(ps)]
    for p in nonroot:
        t = p[0] ^ key[0]
        if t not in (2, 5, 10, 13): continue
        n = ((p[3] ^ key[3]) << 8) | (p[4] ^ key[4])
        cs = ((p[5] ^ key[5]) << 8) | (p[6] ^ key[6]) or 65536
        pe = (12 if t in (2, 5) else 8) + 2 * n
        if pe <= cs <= ps:
            for i in range(pe, cs): votes[i][p[i]] += 1
    unvoted = low_confidence = 0
    for i in range(8, ps):
        if votes[i]:
            (val, n1), total = votes[i].most_common(1)[0], sum(votes[i].values())
            key[i] = val
            if total < 3 or n1 / total < 0.75: low_confidence += 1
        else:
            unvoted += 1
    if unvoted or low_confidence:
        log.warning('derive-key: %d of %d byte positions had no vote (left at the whole-file most-common-byte '
                    'default), %d had a weak majority (<3 samples or <75%% agreement); recovered keystream may '
                    'be unreliable at those offsets, especially on databases with little free page space',
                    unvoted, ps - 8, low_confidence)
    key[:8] = kp[:8]
    return bytes(key)

# --------------------------------------------------------------------------- WAL

def wal_cksum(data, s0, s1, big):
    v = struct.unpack(('>' if big else '<') + '%dI' % (len(data) // 4), data)
    for i in range(0, len(v), 2):
        s0 = (s0 + v[i] + s1) & 0xFFFFFFFF; s1 = (s1 + v[i + 1] + s0) & 0xFFFFFFFF
    return s0, s1

def parse_wal(wal, ps):
    """Return (header, frames). Each frame: dict(idx, pgno, commit, data, valid, reason).
    'valid' follows SQLite's rules on the bytes as stored (checksums cover stored bytes)."""
    if not wal or len(wal) < 32: return None, []
    magic, ver, wps, ckpt, salt1, salt2, c1, c2 = struct.unpack('>8I', wal[:32])
    if magic not in (0x377F0682, 0x377F0683):
        log.warning('WAL magic not recognised (%08x), WAL ignored', magic); return None, []
    if wps != ps:
        log.warning('WAL page size %d differs from database page size %d', wps, ps)
    big = magic & 1
    s0, s1 = wal_cksum(wal[:24], 0, 0, big)
    hdr_ok = (s0, s1) == (c1, c2)
    hdr = {'magic': hex(magic), 'version': ver, 'page_size': wps, 'checkpoint_seq': ckpt,
           'salt1': salt1, 'salt2': salt2, 'header_checksum_ok': hdr_ok, 'big_endian_cksum': bool(big)}
    frames, off, chain_ok, idx = [], 32, hdr_ok, 0
    while off + 24 + wps <= len(wal):
        idx += 1
        pg, commit, fs1, fs2, k1, k2 = struct.unpack('>6I', wal[off:off + 24])
        data = wal[off + 24:off + 24 + wps]
        reason = ''
        if chain_ok:
            if (fs1, fs2) != (salt1, salt2):
                chain_ok = False; reason = 'salt mismatch (stale frame from older WAL generation)'
            else:
                s0, s1 = wal_cksum(wal[off:off + 8], s0, s1, big); s0, s1 = wal_cksum(data, s0, s1, big)
                if (s0, s1) != (k1, k2): chain_ok = False; reason = 'checksum chain broken'
        else:
            reason = reason or 'after end of valid chain'
        frames.append({'idx': idx, 'pgno': pg, 'commit': commit, 'data': data, 'valid': chain_ok,
                       'reason': reason, 'salt': (fs1, fs2), 'offset': off})
        off += 24 + wps
    # frames after the last valid commit are uncommitted
    last_commit = max([f['idx'] for f in frames if f['valid'] and f['commit']] or [0])
    for f in frames:
        if f['valid'] and f['idx'] > last_commit:
            f['valid'] = False; f['reason'] = 'uncommitted (after last commit frame)'
    hdr['frames_total'] = len(frames)
    hdr['frames_committed'] = sum(1 for f in frames if f['valid'])
    hdr['commits'] = sum(1 for f in frames if f['valid'] and f['commit'])
    return hdr, frames

def build_wal_file(hdr_bytes, frames_plain, big):
    out = bytearray(hdr_bytes)
    s0, s1 = wal_cksum(bytes(hdr_bytes[:24]), 0, 0, big)
    out[24:32] = struct.pack('>2I', s0, s1)
    for fh, data in frames_plain:
        s0, s1 = wal_cksum(fh[:8], s0, s1, big); s0, s1 = wal_cksum(data, s0, s1, big)
        out += fh[:16] + struct.pack('>2I', s0, s1) + data
    return bytes(out)

# --------------------------------------------------------------------------- record carving

def varint(b, i):
    v = 0
    for k in range(9):
        if i >= len(b): return None, i
        c = b[i]; i += 1
        if k == 8: return (v << 8) | c, i
        v = (v << 7) | (c & 0x7F)
        if not c & 0x80: return v, i
    return v, i

def stlen(t):
    if t in (0, 8, 9): return 0
    if 1 <= t <= 4: return t
    if t == 5: return 6
    if t in (6, 7): return 8
    if t >= 12: return (t - 12) // 2
    return None

def parse_record(b, i, maxcols=40):
    hl, j = varint(b, i)
    if hl is None or hl < 2 or hl > 2 + 9 * maxcols: return None
    he = i + hl; types = []
    while j < he:
        t, j = varint(b, j)
        if t is None or t in (10, 11): return None
        types.append(t)
    if j != he or not types: return None
    vals, p = [], he
    for t in types:
        L = stlen(t)
        if L is None or p + L > len(b): return None
        d = b[p:p + L]; p += L
        if t == 0: v = None
        elif t <= 6: v = int.from_bytes(d, 'big', signed=True)
        elif t == 7: v = struct.unpack('>d', d)[0]
        elif t == 8: v = 0
        elif t == 9: v = 1
        elif t % 2 == 0: v = bytes(d)
        else:
            try: v = d.decode('utf-8')
            except UnicodeDecodeError: return None
            if any(ord(ch) < 9 for ch in v): return None
        vals.append(v)
    return vals, p

def page_free_regions(p, pgno, ps):
    """Unallocated area, freeblocks; whole page for non b-tree pages."""
    b = 100 if pgno == 1 else 0
    t = p[b]
    if t not in (2, 5, 10, 13): return [(0, ps, 'free/overflow page')]
    n = struct.unpack('>H', p[b + 3:b + 5])[0]
    cs = struct.unpack('>H', p[b + 5:b + 7])[0] or 65536
    pe = b + (12 if t in (2, 5) else 8) + 2 * n
    regs = [(pe, min(cs, ps), 'unallocated')]
    fb = struct.unpack('>H', p[b + 1:b + 3])[0]; guard = 0
    while fb and fb + 4 <= ps and guard < 500:
        nx, sz = struct.unpack('>HH', p[fb:fb + 4]); regs.append((fb, min(fb + sz, ps), 'freeblock'))
        fb = nx; guard += 1
    return regs

# --------------------------------------------------------------------------- field decoding

TIME_COL = re.compile(r'(Time|TS|Utc|TimeStamp|Seen|Updated)$|^(Time|Expiry)', re.I)

def decode_row(table, cols, row, L):
    """Return ordered dict of raw + decoded columns."""
    out = collections.OrderedDict()
    r = dict(zip(cols, row))
    for c in cols:
        v = r[c]
        if isinstance(v, (bytes, bytearray)):
            out[c] = v.hex()
        elif isinstance(v, int) and abs(v) > 2 ** 53:
            out[c] = str(v)
        else:
            out[c] = v
        if isinstance(v, int) and TIME_COL.search(c) and ft_ok(v):
            out[c + ' (UTC)'] = ft_str(v)
        elif isinstance(v, int) and re.search(r'(Utc|Seen)$', c) and 946684800 <= v < 4102444800:
            out[c + ' (UTC)'] = datetime.datetime.fromtimestamp(v, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(v, str) and re.search(r'(Date|Updated|TimeStamp)$', c) and TEXT_DATE.match(v):
            out[c + ' (UTC)'] = v if ' ' in v else v + ' 00:00:00'
        if isinstance(v, (bytes, bytearray)) and len(v) == 16 and re.search(r'(Id|GUID)$', c):
            g = guid_le(v); out[c + ' (GUID)'] = g
            if c == 'RuleId': out['RuleId (ASR name)'] = L.asr_name(g)
    # table specific
    if table == 'FileHashes':
        if r.get('VSN') is not None: out['Volume serial'] = '%04X-%04X' % ((r['VSN'] & 0xFFFFFFFF) >> 16, r['VSN'] & 0xFFFF)
        if isinstance(r.get('FileID'), int):
            fid = r['FileID'] & 0xFFFFFFFFFFFFFFFF
            out['MFT entry'] = fid & 0xFFFFFFFFFFFF; out['MFT sequence'] = fid >> 48
        out['MD5 (stored in column SHA1)'] = r['SHA1'].hex() if isinstance(r.get('SHA1'), bytes) else ''
        out['SHA-1 (stored in column MD5)'] = r['MD5'].hex() if isinstance(r.get('MD5'), bytes) else ''
        out['SHA-256'] = r['SHA256'].hex() if isinstance(r.get('SHA256'), bytes) else ''
        c = r.get('CTPH')
        out['ssdeep (CTPH)'] = c.rstrip(b'\0').decode('ascii', 'replace') if isinstance(c, bytes) else ''
        for k in ('PartialCRC1', 'PartialCRC2', 'PartialCRC3', 'KCRC1', 'KCRC2', 'KCRC3', 'KCRC3n'):
            if isinstance(r.get(k), int): out[k + ' (hex)'] = '%08X' % (r[k] & 0xFFFFFFFF)
    if table == 'BackupProcessInfo':
        v = r.get('FirstStartTime')
        out['FirstStartTime meaning'] = ('process start time' if ft_ok(v) else 'opaque 64-bit identifier (not a time)') if v is not None else ''
    if table == 'AttributePersistContext':
        fp = r.get('FilePath') or ''
        m = re.match(r'AsrRuleStateChangeFor:(.+)', fp)
        out['Record kind'] = 'ASR rule state (engine)' if m else 'Path tag (signature)'
        out['ASR rule'] = L.asr_name(m.group(1)) if m else ''
        out['Context label'] = L.label(r.get('Context'))
    if table in ('RollingQueuesValues', 'RollingQueuesTables'):
        name = r.get('EntryTable') if table == 'RollingQueuesValues' else r.get('Name')
        m = re.search(r'^(Inherited)?(Tech|Tact)-pid:(\d+),ProcessStart:(\d+)', name or '')
        if m:
            out['Queue type'] = ('Inherited ' if m.group(1) else '') + ('techniques of process' if m.group(2) == 'Tech' else 'tactics/rules of process')
            out['PID'] = int(m.group(3)); out['Process start (UTC)'] = ft_str(int(m.group(4)))
        else:
            out['Queue type'] = L.label(name) or 'global/named queue'
            out['PID'] = ''; out['Process start (UTC)'] = ''
        if table == 'RollingQueuesValues':
            k = r.get('EntryKey') or ''
            km = re.search(r'pid:(\d+),ProcessStart:(\d+)', k)
            if km and not out['PID']:
                out['PID'] = int(km.group(1)); out['Process start (UTC)'] = ft_str(int(km.group(2)))
            if m:
                tname = L.technique(k) if re.match(r'^T\d{4}', k) else ''
                out['EntryKey label'] = '; '.join(x for x in (('ATT&CK %s %s' % (k, tname)) if tname else '',
                    'Defender per-process attack scoring entry (%s)' % ('technique' if m.group(2) == 'Tech' else 'tactic/rule name')) if x)
            else:
                out['EntryKey label'] = L.label(k)
            ev = r.get('EntryValue')
            out['EntryValue decoded'] = ''
            if isinstance(ev, str) and ev[:1] in '{[':
                try:
                    j = json.loads(ev)
                    if isinstance(j, dict):
                        pid = j.get('ProcessId')
                        if isinstance(pid, str):
                            pm = re.search(r'pid:(\d+),ProcessStart:(\d+)', pid)
                            if pm:
                                j['ProcessId'] = 'pid %s started %s UTC' % (pm.group(1), ft_str(int(pm.group(2))))
                                if not out['PID']: out['PID'] = int(pm.group(1)); out['Process start (UTC)'] = ft_str(int(pm.group(2)))
                        if j.get('Process_Img'): out['Process image'] = j['Process_Img']
                        if j.get('FileAttributes'): out['Signature attributes'] = j['FileAttributes']
                    out['EntryValue decoded'] = json.dumps(j, ensure_ascii=False)
                except ValueError:
                    out['EntryValue decoded'] = '(truncated or invalid JSON)'
        else:
            ttl = r.get('TimeToLive')
            out['TimeToLive (h)'] = round(ttl / 3600, 2) if isinstance(ttl, int) else ''
    if table.startswith('MetaInventory'):
        if isinstance(r.get('JournalId'), int) and ft_ok(r['JournalId']):
            out['USN journal created'] = ft_str(r['JournalId'])
        if isinstance(r.get('VolumeSerial'), int):
            out['Volume serial (hex)'] = '%016X' % (r['VolumeSerial'] & 0xFFFFFFFFFFFFFFFF)
        if isinstance(r.get('FileIdLo'), int) and not r.get('FileIdHi'):
            fid = r['FileIdLo'] & 0xFFFFFFFFFFFFFFFF
            out['MFT entry'] = fid & 0xFFFFFFFFFFFF; out['MFT sequence'] = fid >> 48
        if 'PropertyKind' in r and table == 'MetaInventoryFileCache':
            out['PropertyKind meaning'] = {1: 'file version info', 4: 'PowerShell module', 6: 'Java runtime'}.get(r['PropertyKind'], '')
            out['Payload decoded'] = ' | '.join(tlv_strings(r.get('Payload')))
        if table == 'MetaInventoryIdentifiers':
            out['Kind meaning'] = {1: 'CPE', 2: 'package URL'}.get(r.get('Kind'), '')
            out['Known vulnerabilities'] = ', '.join(L.vulns.get(r.get('Identifier'), []))
    if table == 'FileLowFiAsync':
        out['SigSha (hex)'] = r['SigSha'].hex() if isinstance(r.get('SigSha'), bytes) else ''
    return out

def plausibility(cols, vals):
    """Flag carved records whose tail was overwritten: impossible times or expiry before insert."""
    r = dict(zip(cols, vals)); bad = []
    for c, v in r.items():
        if isinstance(v, int) and TIME_COL.search(c) and v not in (0,) and not ft_ok(v) and c not in ('FirstStartTime',):
            bad.append(c)
    it, et = r.get('InsertTime'), r.get('ExpireTime')
    if ft_ok(it) and ft_ok(et) and et < it: bad.append('ExpireTime<InsertTime')
    for c, v in r.items():
        if c in ('NextUSN', 'USN') and isinstance(v, int) and v < 0: bad.append(c)
    return 'consistent' if not bad else 'partially overwritten, implausible: ' + ', '.join(bad)

def tlv_strings(b):
    """MetaInventory payload: repeated [1-byte field id][4-byte LE length][UTF-8 value]."""
    out, i = [], 0
    if not isinstance(b, (bytes, bytearray)): return out
    while i + 5 <= len(b):
        n = struct.unpack_from('<I', b, i + 1)[0]
        if i + 5 + n > len(b): out.append('(truncated)'); break
        out.append('%d=%s' % (b[i], b[i + 5:i + 5 + n].decode('utf-8', 'replace'))); i += 5 + n
    return out

TEXT_DATE = re.compile(r'^\d{4}-\d{2}-\d{2}( \d{2}:\d{2}:\d{2})?$')

def describe_event(table, d):
    """One timeline line per row: (time column, description, object)."""
    if table == 'AttributePersistContext':
        return 'Context "%s" %s' % (d.get('Context'), ('ASR ' + d['ASR rule']) if d.get('ASR rule') else ''), d.get('FilePath')
    if table == 'RollingQueuesValues':
        who = ('pid %s (started %s)' % (d['PID'], d['Process start (UTC)'])) if d.get('PID') else ''
        lbl = d.get('EntryKey label') or ''
        return ' '.join(x for x in ('Queue %s: %s' % (d.get('EntryTable'), d.get('EntryKey')), ('[' + lbl + ']') if lbl else '', who) if x), d.get('EntryKey')
    if table == 'FileHashes':
        return 'File hashed by real-time protection, SHA-256 %s, MFT %s/%s on volume %s' % (
            d.get('SHA-256'), d.get('MFT entry'), d.get('MFT sequence'), d.get('Volume serial')), 'MFT %s' % d.get('MFT entry')
    if table == 'BackupProcessInfo':
        return 'Tracked for ransomware rollback (NextUSN %s)' % d.get('NextUSN'), d.get('FilePath')
    if table == 'FileLowFiAsync':
        return 'LowFi signature hit sent for async cloud lookup (SigSeq %s)' % d.get('SigSeq'), d.get('FileName')
    if table == 'BmProcessInfo':
        return 'Behaviour-monitored process pid %s %s' % (d.get('PID'), d.get('CommandLineArgs') or ''), d.get('ImageFileName')
    if table == 'ProcessBlockHistory':
        return 'Process blocked (audit=%s) target %s %s' % (d.get('IsAudit'), d.get('TargetPath'), d.get('RuleId (ASR name)', '')), d.get('ProcessPath')
    if table == 'RansomwareDetections':
        return 'Ransomware detection %s' % d.get('DetectionGuid'), d.get('DetectionGuid')
    if table == 'MetaInventoryIdentifiers':
        v = d.get('Known vulnerabilities')
        return 'Software inventory: %s %s' % (d.get('Kind meaning'), ('(known vulnerabilities: %s)' % v) if v else ''), d.get('Identifier')
    if table == 'MetaInventorySnapshots':
        return 'Software inventory run, %s identifiers' % d.get('IdentifierCount'), d.get('InventoryId')
    if table == 'MetaInventoryFileCache':
        return 'Inventory file property cached (%s): %s' % (d.get('PropertyKind meaning'), d.get('Payload decoded', '')[:200]), 'MFT %s' % d.get('MFT entry')
    obj = next((d[k] for k in ('FilePath', 'Path', 'Name', 'FileName', 'ImageFileName', 'Identifier', 'FirewallRuleName') if d.get(k)), '')
    return 'Row in %s' % table, obj

# --------------------------------------------------------------------------- recovered-row CSV expansion

def recovered_csv_columns(rows):
    """Expand JSON object keys into CSV columns without losing the original JSON.

    The first five columns retain their original names/order for compatibility.
    JSON fields are collected from all recovered tables, so differing schemas
    get blank cells rather than losing information. Unparseable/non-object JSON
    is left in 'Decoded row (JSON)' with the new columns blank.
    """
    base = ['Method', 'Record quality', 'Location', 'Table', 'Decoded row (JSON)']
    fields, seen, parsed_rows = [], set(base), []
    for row in rows:
        try:
            obj = json.loads(row[4])
        except (TypeError, ValueError):
            obj = None
        parsed = {}
        if isinstance(obj, dict):
            for key, value in obj.items():
                # Avoid clobbering export metadata with identically named fields.
                col = key if key not in base else 'Row ' + key
                if col not in seen:
                    fields.append(col)
                    seen.add(col)
                # Nested values remain valid JSON inside a single CSV cell.
                parsed[col] = (json.dumps(value, ensure_ascii=False)
                               if isinstance(value, (dict, list, bool)) else value)
        parsed_rows.append(parsed)
    return (base + fields,
            [list(row) + [parsed.get(k, '') for k in fields]
             for row, parsed in zip(rows, parsed_rows)])

# --------------------------------------------------------------------------- main work

class Parser:
    def __init__(self, a):
        self.a = a; self.out = a.out; os.makedirs(self.out, exist_ok=True)
        self.summary = collections.OrderedDict(); self.outputs = []
        self.L = Lookups(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'lookups'))

    def wcsv(self, name, header, rows):
        p = os.path.join(self.out, name)
        with open(p, 'w', newline='', encoding='utf-8-sig') as f:
            w = csv.writer(f); w.writerow(header); w.writerows(rows)
        self.outputs.append(p); return p

    def run(self):
        a = self.a
        db_path, wal_path = self.locate()
        self.summary['tool'] = '%s %s' % (TOOL, VERSION)
        self.summary['run_started'] = utcnow()
        self.summary['python'] = sys.version.split()[0]
        self.summary['sqlite_library'] = sqlite3.sqlite_version
        ev = collections.OrderedDict()
        for p in (db_path, wal_path):
            if p: ev[p] = file_hashes(p); log.info('evidence %s sha256 %s size %d', p, ev[p]['sha256'], ev[p]['size'])
        self.summary['evidence'] = ev
        db = open(db_path, 'rb').read()
        wal = open(wal_path, 'rb').read() if wal_path else b''

        # ---- page size and protection
        ps = struct.unpack('>H', db[16:18])[0]; ps = 65536 if ps == 1 else ps
        if ps < 512 or ps & (ps - 1) or len(db) % ps:
            raise SystemExit('Not a MetaVault/SQLite file: page size field %d, file size %d' % (ps, len(db)))
        pages = [db[i:i + ps] for i in range(0, len(db), ps)]
        whdr, frames = parse_wal(wal, ps)
        if db[:16] == MAGIC:
            codec = None; self.summary['protection'] = 'none (plain SQLite, codec disabled)'
            log.info('database header is plain SQLite: codec not active')
        else:
            ks, how = None, None
            for name, key in ({} if self.a.derive_key else KNOWN_KEYS).items():
                cand = rc4_stream(key, ps)
                if xor(db[:16], cand[:16]) == MAGIC: ks, how = cand, 'known key ' + name; break
            if ks is None:
                log.info('no known key matched, recovering keystream from the file')
                ks = derive_keystream(pages, [f['data'] for f in frames if f['pgno'] != 1], ps)
                how = 'recovered from file (known plaintext + free space)'
            codec = Codec(ks, ps)
            if codec.page(db[:ps], 1)[:16] != MAGIC: raise SystemExit('Decryption failed: header does not match')
            self.summary['protection'] = 'RC4 page codec, keystream: ' + how
            self.summary['keystream_sha256'] = hashlib.sha256(ks).hexdigest()
            log.info('protection: %s', self.summary['protection'])
        dec = (lambda d, n: codec.page(d, n)) if codec else (lambda d, n: d)
        plain_pages = [dec(p, i + 1) for i, p in enumerate(pages)]
        for f in frames: f['plain'] = dec(f['data'], f['pgno'])
        self.summary['page_size'] = ps; self.summary['db_pages'] = len(pages)
        self.summary['wal'] = {k: v for k, v in (whdr or {}).items()}

        # ---- states: base + every valid commit
        states = [('S00', 'database file without WAL', bytes(b''.join(plain_pages)))]
        cur = bytearray(b''.join(plain_pages)); k = 0
        for f in frames:
            if not f['valid']: continue
            need = f['pgno'] * ps
            if len(cur) < need: cur += b'\0' * (need - len(cur))
            cur[(f['pgno'] - 1) * ps:f['pgno'] * ps] = f['plain']
            if f['commit']:
                k += 1; states.append(('S%02d' % k, 'after WAL commit %d (frame %d)' % (k, f['idx']), bytes(cur[:f['commit'] * ps])))
        sdir = os.path.join(self.out, 'states'); os.makedirs(sdir, exist_ok=True)
        state_files = []
        for sid, desc, blob in states:
            p = os.path.join(sdir, sid + '.db'); open(p, 'wb').write(blob); state_files.append((sid, desc, p))
        final = state_files[-1][2]
        def journal_mode(blob):   # outputs are complete images: mark them rollback-journal so no -wal is expected
            b = bytearray(blob); b[18] = 1; b[19] = 1; return bytes(b)
        merged = os.path.join(self.out, 'mpenginedb_decrypted.db')
        open(merged, 'wb').write(journal_mode(open(final, 'rb').read())); self.outputs.append(merged)
        base_out = os.path.join(self.out, 'mpenginedb_decrypted_without_wal.db')
        open(base_out, 'wb').write(journal_mode(states[0][2])); self.outputs.append(base_out)
        self.summary['states'] = [{'id': s, 'description': d} for s, d, _ in state_files]

        # ---- integrity of every state, read all rows
        rows_by_state = []; schema = {}
        for sid, desc, p in state_files:
            c = sqlite3.connect('file:%s?mode=ro&immutable=1' % p, uri=True)
            c.text_factory = lambda b: b.decode('utf-8', 'replace')
            try:
                ic = c.execute('pragma integrity_check').fetchone()[0]
            except (sqlite3.DatabaseError, UnicodeDecodeError) as e:
                ic = 'error: %s' % e
            log.info('state %s (%s): integrity_check %s', sid, desc, ic)
            if ic != 'ok':
                log.warning('state %s: integrity_check did not pass; affected tables/rows in this state are '
                            'skipped below rather than failing the whole run, other states are unaffected', sid)
            st = {}
            try:
                tables = [t for (t,) in c.execute(
                    "select name from sqlite_master where type='table' order by name")]
            except (sqlite3.DatabaseError, UnicodeDecodeError) as e:
                log.warning('state %s: could not list tables (%s)', sid, e); tables = []
            for t in tables:
                try:
                    cu = c.execute('select * from "%s"' % t)
                    schema[t] = [x[0] for x in cu.description]; st[t] = cu.fetchall()
                except (sqlite3.DatabaseError, UnicodeDecodeError) as e:
                    log.warning('state %s: table %r unreadable (%s), skipped for this state', sid, t, e)
                    schema.setdefault(t, [])
            if sid == 'S00':
                self.summary['schema_tables'] = len([t for t in st if not t.startswith('sqlite_')])
            rows_by_state.append((sid, ic, st)); c.close()
        self.summary['integrity'] = {s: ic for s, ic, _ in rows_by_state}
        final_rows = rows_by_state[-1][2]
        pk = {}; self.aff = {}
        c = sqlite3.connect('file:%s?mode=ro&immutable=1' % final, uri=True)
        c.text_factory = lambda b: b.decode('utf-8', 'replace')
        for t in schema:
            try:
                ti = c.execute('pragma table_info("%s")' % t).fetchall()
                self.aff[t] = [self.affinity(x[2]) for x in ti]
                pk[t] = [x[1] for x in ti if x[5] == 1 and x[2].upper() == 'INTEGER' and sum(1 for y in ti if y[5]) == 1]
                sql = c.execute("select sql from sqlite_master where name=?", (t,)).fetchone()[0] or ''
                if 'WITHOUT ROWID' in sql.upper(): pk[t] = []
            except (sqlite3.DatabaseError, UnicodeDecodeError) as e:
                log.warning('final state: could not read table_info for %r (%s), treating it as no primary key', t, e)
                self.aff[t] = []; pk[t] = []
        c.close()

        # ---- history: rows seen in earlier states but not in the final state
        hist = []; seen = collections.OrderedDict()
        for sid, _, st in rows_by_state:
            for t, rs in st.items():
                for r in rs:
                    seen.setdefault((t, r), []).append(sid)
        final_sid = rows_by_state[-1][0]
        for (t, r), sids in seen.items():
            status = 'present in final state' if final_sid in sids else 'deleted or changed during WAL period'
            hist.append((t, r, sids[0], sids[-1], status))
        recovered = [(t, r, 'history', 'in %s..%s, not in final state' % (a1, b1)) for t, r, a1, b1, s in hist if s.startswith('deleted')]

        # ---- carving
        carved = []
        if not a.no_carve:
            live = set()
            for (t, r) in seen: live.add((t, tuple(x for i, x in enumerate(r) if not (pk[t] and schema[t][i] == pk[t][0]))))
            sources = [('db page %d' % (i + 1), i + 1, p) for i, p in enumerate(plain_pages)]
            sources += [('WAL frame %d (%s)' % (f['idx'], 'committed' if f['valid'] else f['reason']), f['pgno'], f['plain']) for f in frames]
            sigs = {}
            for t, cols in schema.items():
                if t.startswith('sqlite_'): continue
                sigs[t] = cols
            seen_carve = {}
            for src, pg, p in sources:
                for s, e, kind in page_free_regions(p, pg, ps):
                    i = s
                    while i < e - 3:
                        res = parse_record(p, i)
                        if res:
                            vals, end = res; m = self.match(vals, sigs, pk)
                            if m:
                                key = tuple(x for j, x in enumerate(vals) if not (pk[m] and schema[m][j] == pk[m][0]))
                                if (m, key) not in live:
                                    seen_carve.setdefault((m, tuple(vals)), []).append('%s @%d (%s)' % (src, i, kind))
                                i = end; continue
                        i += 1
            live_ids = set()
            for (t, r) in seen:
                i = self.identity(t, schema[t], list(r))
                if i: live_ids.add(i)
            for (t, vals), locs in seen_carve.items():
                i = self.identity(t, schema[t], list(vals))
                kind = 'carved: older version of a live row' if i and i in live_ids else 'carved: deleted row'
                carved.append((t, vals, kind, '; '.join(locs[:5]) + (' (+%d more)' % (len(locs) - 5) if len(locs) > 5 else '')))
            log.info('carving: %d record(s) not present in any state', len(carved))
        self.summary['recovered_rows_history'] = len(recovered); self.summary['recovered_rows_carved'] = len(carved)
        self.summary['carved_by_kind'] = dict(collections.Counter(k for _, _, k, _ in carved))

        # ---- software inventory: identifier -> CVE list
        self.L.vulns = collections.defaultdict(list)
        cols_iv = schema.get('MetaInventoryIdentifierVulnerabilities')
        for r in final_rows.get('MetaInventoryIdentifierVulnerabilities', []):
            d = dict(zip(cols_iv, r)); self.L.vulns[d['Identifier']].append(d['VulnerabilityId'])

        # ---- outputs per table
        tl = []; counts = collections.OrderedDict()
        tdir = os.path.join(self.out, 'tables'); os.makedirs(tdir, exist_ok=True)
        for t in sorted(schema):
            rs = final_rows.get(t, [])
            counts[t] = len(rs)
            if not rs and not a.all_tables: continue
            decoded = [decode_row(t, schema[t], r, self.L) for r in rs]
            hdr = list(collections.OrderedDict((k, 1) for d in decoded for k in d).keys()) or schema[t]
            self.wcsv(os.path.join('tables', t + '.csv'), hdr, [[d.get(k, '') for k in hdr] for d in decoded])
            for d in decoded: self.timeline_rows(t, d, 'live (final state)', tl)
        self.summary['row_counts_final'] = counts

        # recovered rows
        rec_rows = []
        for t, vals, how, where in recovered + carved:
            cols = schema.get(t, ['c%d' % i for i in range(len(vals))])
            vals = list(vals) + [None] * (len(cols) - len(vals))
            d = decode_row(t, cols, vals, self.L)
            q = plausibility(cols, vals) if how.startswith('carved') else 'consistent (complete row from a committed state)'
            rec_rows.append([how, q, where, t, json.dumps(d, ensure_ascii=False, default=str)])
            self.timeline_rows(t, d, 'RECOVERED (%s%s)' % (how, '' if q.startswith('consistent') else '; ' + q), tl)
        rec_header, rec_csv_rows = recovered_csv_columns(rec_rows)
        self.wcsv('recovered_rows.csv', rec_header, rec_csv_rows)
        self.summary['recovered_partially_overwritten'] = sum(1 for x in rec_rows if not x[1].startswith('consistent'))
        self.wcsv('row_history.csv', ['Table', 'First state', 'Last state', 'Status', 'Row (JSON)'],
                  [[t, a1, b1, s, json.dumps(list(r), default=lambda x: x.hex() if isinstance(x, bytes) else str(x))] for t, r, a1, b1, s in hist])

        # schema versions (tamper indicator)
        sg = final_rows.get('SQLiteGlobals', [])
        if sg:
            vers = sorted((r[1], r[3]) for r in sg)
            self.summary['schema_versions'] = [{'version': v, 'date': d} for v, d in vers]
            self.summary['schema_note'] = ('single schema row: the database was created by an engine already at this schema version. '
                                           'Normal on a recent install; on an older system it means the database was recreated (compare with install date)'
                                           if len(vers) == 1 else 'database created at schema v%s and upgraded %d time(s); created no later than %s' % (vers[0][0], len(vers) - 1, vers[0][1]))

        tl.sort(key=lambda x: x[0])
        self.wcsv('timeline.csv', ['Time (UTC)', 'Time column', 'Table', 'Source', 'Event', 'Object', 'Row ID'], tl)
        self.summary['timeline_events'] = len(tl)

        # WAL frame map
        self.wcsv('wal_frames.csv', ['Frame', 'File offset', 'Page', 'Commit size', 'Valid', 'Note'],
                  [[f['idx'], f['offset'], f['pgno'], f['commit'], f['valid'], f['reason']] for f in frames])

        if not a.keep_states:
            for _, _, p in state_files: os.remove(p)
            os.rmdir(sdir)
        else:
            self.outputs += [p for _, _, p in state_files]

        # evidence unchanged?
        after = {p: file_hashes(p)['sha256'] for p in ev}
        self.summary['evidence_unchanged'] = all(after[p] == ev[p]['sha256'] for p in ev)
        self.summary['lookups'] = self.L.meta
        self.summary['run_finished'] = utcnow()
        sp = os.path.join(self.out, 'summary.json')
        json.dump(self.summary, open(sp, 'w', encoding='utf-8'), indent=2, default=str); self.outputs.append(sp)
        self.write_report()
        log.info('done: %d timeline events, %d recovered (history), %d carved; writing manifest (run.log is complete at this line)', len(tl), len(recovered), len(carved))
        self.write_manifest()

    @staticmethod
    def affinity(decl):
        d = (decl or '').upper()
        if 'INT' in d: return 'INTEGER'
        if any(x in d for x in ('CHAR', 'CLOB', 'TEXT')): return 'TEXT'
        if 'BLOB' in d or not d: return 'BLOB'
        if any(x in d for x in ('REAL', 'FLOA', 'DOUB')): return 'REAL'
        return 'NUMERIC'

    def match(self, vals, sigs, pk):
        """Match a carved record to a table by column count and declared column types."""
        best = None
        for t, cols in sigs.items():
            if len(cols) != len(vals): continue
            aff = self.aff[t]
            if 'TEXT' not in aff: continue            # numeric-only tables are too ambiguous to carve
            if pk[t] and vals[cols.index(pk[t][0])] is not None: continue
            score, ok, strs = 0, True, 0
            for c, a, v in zip(cols, aff, vals):
                if v is None: continue
                if a == 'INTEGER' and not isinstance(v, int): ok = False; break
                if a == 'TEXT' and not isinstance(v, str): ok = False; break
                if a in ('REAL', 'NUMERIC') and not isinstance(v, (int, float)): ok = False; break
                if a == 'BLOB' and not isinstance(v, (bytes, str, int, float)): ok = False; break
                score += 2 if a == 'TEXT' else 1; strs += isinstance(v, str) and len(v) >= 3
            if not ok or strs == 0 or score < 3: continue
            if best is None or score > best[1]: best = (t, score)
        return best[0] if best else None

    IDENTITY = {'RollingQueuesValues': ('EntryTable', 'EntryKey'), 'AttributePersistContext': ('FilePath', 'Context'),
                'RollingQueuesTables': ('Name', 'Namespace'), 'BackupProcessInfo': ('FilePath',),
                'FileLowFiAsync': ('FileName',), 'AtomicCounters': ('Name', 'Namespace'), 'AttributeCounts': ('Name',)}

    def identity(self, t, cols, vals):
        keys = self.IDENTITY.get(t) or (('Key',) if 'Key' in cols else None)
        if not keys: return None
        return (t,) + tuple(vals[cols.index(k)] if k in cols and cols.index(k) < len(vals) else None for k in keys)

    def timeline_rows(self, t, d, source, tl):
        ev, obj = describe_event(t, d)
        for k, v in d.items():
            if k.endswith(' (UTC)') and v and k != 'Process start (UTC)':
                tl.append([v, k[:-6], t, source, ev, obj if obj is not None else '', d.get('ID', '')])

    def locate(self):
        f = self.a.file
        if os.path.isdir(f): f = os.path.join(f, 'mpenginedb.db')
        if not os.path.isfile(f): raise SystemExit('database not found: %s' % f)
        w = self.a.wal or (f + '-wal' if os.path.isfile(f + '-wal') else None)
        if w and not os.path.isfile(w): raise SystemExit('WAL not found: %s' % w)
        if not w: log.warning('no WAL file supplied or found next to the database: newest changes may be missing')
        return f, w

    def write_report(self):
        s = self.summary; p = os.path.join(self.out, 'report.txt')
        L = ['%s %s report' % (TOOL, VERSION), '=' * 60, 'Run: %s .. %s' % (s['run_started'], s['run_finished']), '']
        L.append('Evidence');
        for k, v in s['evidence'].items(): L.append('  %s\n    size %d  md5 %s\n    sha1 %s\n    sha256 %s' % (k, v['size'], v['md5'], v['sha1'], v['sha256']))
        L.append('  evidence unchanged after run: %s' % s['evidence_unchanged'])
        L += ['', 'Protection: %s' % s['protection'], 'Pages: %d x %d bytes' % (s['db_pages'], s['page_size'])]
        if s.get('wal'): L.append('WAL: %d frames, %d committed, %d commits' % (s['wal'].get('frames_total', 0), s['wal'].get('frames_committed', 0), s['wal'].get('commits', 0)))
        L.append('Integrity: ' + ', '.join('%s=%s' % kv for kv in s['integrity'].items()))
        if s.get('schema_versions'):
            L += ['', 'Schema versions (creation / upgrade history):'] + ['  v%s  %s' % (x['version'], x['date']) for x in s['schema_versions']] + ['  -> ' + s['schema_note']]
        L += ['', 'Rows in final state (non-empty tables):'] + ['  %-34s %d' % kv for kv in s['row_counts_final'].items() if kv[1]]
        L += ['', 'Recovered rows: %d from WAL history, %d carved (%d partially overwritten, see Record quality)' % (s['recovered_rows_history'], s['recovered_rows_carved'], s.get('recovered_partially_overwritten', 0)),
              'Timeline events: %d' % s['timeline_events'], '',
              'Notes', '  All times are UTC. FILETIME values decoded with 100 ns precision.',
              '  FileHashes: column SHA1 holds MD5 and column MD5 holds SHA-1 (Defender schema naming).',
              '  Labels come from MITRE ATT&CK, Microsoft ASR documentation and Defender signature analysis (see lookups).']
        open(p, 'w', encoding='utf-8').write('\n'.join(L) + '\n'); self.outputs.append(p)

    def write_manifest(self):
        p = os.path.join(self.out, 'manifest.csv')
        logp = os.path.join(self.out, 'run.log')
        for h in log.handlers: h.flush()
        files = self.outputs + [logp]
        with open(p, 'w', newline='', encoding='utf-8') as f:
            w = csv.writer(f); w.writerow(['File', 'Size', 'SHA-256'])
            for x in files:
                if os.path.exists(x): w.writerow([os.path.relpath(x, self.out), os.path.getsize(x), file_hashes(x)['sha256']])

def main():
    ap = argparse.ArgumentParser(description='Forensic parser for Microsoft Defender mpenginedb.db (MetaVault)')
    ap.add_argument('-f', '--file', required=True, help='mpenginedb.db or the folder containing it')
    ap.add_argument('--wal', help='WAL file if not next to the database as <db>-wal')
    ap.add_argument('-o', '--out', required=True, help='output folder')
    ap.add_argument('--keep-states', action='store_true', help='keep the rebuilt database of every WAL commit')
    ap.add_argument('--no-carve', action='store_true', help='skip carving of deleted records')
    ap.add_argument('--all-tables', action='store_true', help='write CSV files for empty tables too')
    ap.add_argument('--derive-key', action='store_true', help='ignore built-in keys and recover the keystream from the evidence only')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s UTC %(levelname)s %(message)s',
                        handlers=[logging.FileHandler(os.path.join(a.out, 'run.log'), encoding='utf-8'), logging.StreamHandler()])
    logging.Formatter.converter = time.gmtime
    log.info('%s %s started, args: %s', TOOL, VERSION, vars(a))
    try:
        Parser(a).run()
    except SystemExit as e:
        if e.code not in (0, None): log.error('stopped: %s', e.code)
        raise
    except Exception:
        log.exception('unexpected error'); raise SystemExit(2)

if __name__ == '__main__':
    main()
