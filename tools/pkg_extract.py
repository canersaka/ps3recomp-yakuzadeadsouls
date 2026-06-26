"""pkg_extract.py - extract files from a PS3 .pkg (no RPCS3 GUI needed).

Handles both finalized (retail, AES-128-CTR with the public PS3_GPKG key) and
non-finalized/debug (SHA-1 keystream) packages. DRM-free (type 3) content needs
no per-title RAP/klicensee, so the whole PlayStation Minis catalog opens up.

Auto-detects the keystream by checking that the decrypted file table yields
ASCII filenames. Usage:
    python pkg_extract.py <in.pkg> <out_dir> [--only EBOOT.BIN]
"""
import hashlib, os, struct, sys

PS3_GPKG_KEY = bytes.fromhex("2e7b71d7c9c9a14ea3221f188828b8f8")

# --- tiny pure-python AES-128 ECB (only the encrypt path; for CTR keystream) ---
_sbox = []
def _init_aes():
    p = q = 1
    sbox = [0]*256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1; q ^= q << 2; q ^= q << 4; q &= 0xFF
        if q & 0x80: q ^= 0x09
        x = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (x ^ 0x63) & 0xFF
        if p == 1: break
    sbox[0] = 0x63
    return sbox
def _xtime(a): return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1)
def _aes_expand(key):
    sbox = _sbox
    rcon = 1; w = [list(key[i*4:i*4+4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [sbox[b] for b in t]
            t[0] ^= rcon; rcon = _xtime(rcon)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return w
def _aes_encrypt_block(key_sched, block):
    sbox = _sbox
    s = [[block[r+4*c] for c in range(4)] for r in range(4)]
    def addrk(rnd):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= key_sched[rnd*4+c][r]
    addrk(0)
    for rnd in range(1, 10):
        for r in range(4):
            for c in range(4):
                s[r][c] = sbox[s[r][c]]
        s[1] = s[1][1:] + s[1][:1]
        s[2] = s[2][2:] + s[2][:2]
        s[3] = s[3][3:] + s[3][:3]
        for c in range(4):
            a = [s[r][c] for r in range(4)]
            s[0][c] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
            s[3][c] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])
        addrk(rnd)
    for r in range(4):
        for c in range(4):
            s[r][c] = sbox[s[r][c]]
    s[1] = s[1][1:] + s[1][:1]; s[2] = s[2][2:] + s[2][:2]; s[3] = s[3][3:] + s[3][:3]
    addrk(10)
    return bytes(s[r][c] for c in range(4) for r in range(4))

def ctr_keystream(riv, nblocks, sched):
    ctr = int.from_bytes(riv, "big"); out = bytearray()
    for _ in range(nblocks):
        out += _aes_encrypt_block(sched, ctr.to_bytes(16, "big"))
        ctr = (ctr + 1) & ((1 << 128) - 1)
    return bytes(out)

def debug_keystream(hdr60, nblocks):
    out = bytearray()
    for n in range(nblocks):
        k = bytearray(hdr60)              # 0x40 bytes from header 0x60..0xA0
        ctr = int.from_bytes(k[0x38:0x40], "big") + n
        k[0x38:0x40] = (ctr & ((1 << 64) - 1)).to_bytes(8, "big")
        out += hashlib.sha1(bytes(k)).digest()[:0x10]
    return bytes(out)

def main():
    global _sbox
    inp, outd = sys.argv[1], sys.argv[2]
    only = None
    if "--only" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1]
    data = open(inp, "rb").read()
    assert data[:4] == b"\x7fPKG", "not a PKG"
    rev = struct.unpack(">H", data[4:6])[0]
    item_count = struct.unpack(">I", data[0x14:0x18])[0]
    data_off = struct.unpack(">Q", data[0x20:0x28])[0]
    data_size = struct.unpack(">Q", data[0x28:0x30])[0]
    riv = data[0x70:0x80]; hdr60 = data[0x60:0xA0]
    enc = data[data_off:data_off + data_size]
    nblocks = (len(enc) + 15) // 16
    _sbox = _init_aes()
    sched = _aes_expand(PS3_GPKG_KEY)

    # try both keystreams; accept the one whose file table has ASCII names
    def try_ks(ks):
        dec = bytes(a ^ b for a, b in zip(enc, ks[:len(enc)]))
        names = []
        for i in range(item_count):
            e = dec[i*0x20:(i+1)*0x20]
            if len(e) < 0x20: return None
            no, ns = struct.unpack(">II", e[:8])
            fo, fs = struct.unpack(">QQ", e[8:0x18])
            nm = dec[no:no+ns]
            if not nm or any(c < 0x20 or c > 0x7E for c in nm): return None
            names.append((nm.decode(), fo, fs))
        return dec, names

    res = try_ks(debug_keystream(hdr60, nblocks)) if rev == 0 else None
    used = "debug"
    if res is None:
        res = try_ks(ctr_keystream(riv, nblocks, sched)); used = "finalized"
    if res is None:
        res = try_ks(debug_keystream(hdr60, nblocks)); used = "debug"
    assert res, "could not decrypt file table with either keystream"
    dec, names = res
    print(f"rev=0x{rev:04X} keystream={used} items={item_count}")
    os.makedirs(outd, exist_ok=True)
    for nm, fo, fs in names:
        if only and os.path.basename(nm) != only:
            continue
        blob = dec[fo:fo+fs]
        op = os.path.join(outd, os.path.basename(nm))
        if fs > 0 and blob:
            open(op, "wb").write(blob)
            tag = "  <-- SELF" if blob[:4] == b"SCE\x00" else ""
            print(f"  {nm}  ({fs} bytes){tag}")

if __name__ == "__main__":
    main()
