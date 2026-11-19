"""Danfoss Link CC over Trifork's MDG cloud relay.

Protocol reverse-engineered from the Danfoss Link 1.3.10 app; details and audit trail:
https://github.com/UrbanskiDawid/danfoss-link-cc (README.md, WORKLOG.md).

All calls are blocking; run them in an executor.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import socket
import struct
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RELAYS = ("mdg-danfoss.hosted.trifork.com", "77.66.11.90", "5.179.92.180")
CTL_MAGIC, ROUTING_MAGIC, PACE_MAGIC = 4036857000, 4036856981, 4036856999
TIMEOUT = 30


class LinkError(Exception):
    """Pairing or communication with the panel failed."""


# ---------------------------------------------------------------- elliptic curves


class Curve:
    """Short Weierstrass curve; the stack uses brainpoolP320r1, which `cryptography` lacks."""

    def __init__(self, p, a, b, gx, gy, n, tls_id):
        self.p, self.a, self.b, self.n, self.tls_id = p, a, b, n, tls_id
        self.g = (gx, gy)
        self.size = (p.bit_length() + 7) // 8

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        if P[0] == Q[0]:
            if (P[1] + Q[1]) % p == 0:
                return None
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, p)
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p)
        x = (lam * lam - P[0] - Q[0]) % p
        return x, (lam * (P[0] - x) - P[1]) % p

    def mul(self, P, k):
        R = None
        for bit in bin(k)[2:]:
            R = self.add(R, R)
            if bit == "1":
                R = self.add(R, P)
        return R

    def encode(self, P):
        return b"\x04" + P[0].to_bytes(self.size, "big") + P[1].to_bytes(self.size, "big")

    def decode(self, b):
        s = self.size
        if len(b) != 1 + 2 * s or b[0] != 4:
            raise LinkError("bad EC point")
        x, y = int.from_bytes(b[1 : 1 + s], "big"), int.from_bytes(b[1 + s :], "big")
        if (y * y - x * x * x - self.a * x - self.b) % self.p:
            raise LinkError("EC point not on curve")
        return x, y

    def scalar(self):
        return secrets.randbelow(self.n - 1) + 1

    def _e(self, digest):
        return int.from_bytes(digest, "big") >> max(0, len(digest) * 8 - self.n.bit_length())

    def sign(self, d, digest):
        while True:
            k = self.scalar()
            r = self.mul(self.g, k)[0] % self.n
            s = pow(k, -1, self.n) * (self._e(digest) + r * d) % self.n
            if r and s:
                return _der(0x30, _int(r), _int(s))

    def verify(self, Q, digest, sig):
        r, s = (int.from_bytes(v, "big") for _, v, _ in _children(_children(sig)[0][1]))
        if not (0 < r < self.n and 0 < s < self.n):
            return False
        w = pow(s, -1, self.n)
        R = self.add(self.mul(self.g, self._e(digest) * w % self.n), self.mul(Q, r * w % self.n))
        return R is not None and R[0] % self.n == r


def _h(s):
    return int(s, 16)


BP320 = Curve(
    _h("D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27"),
    _h("3EE30B568FBAB0F883CCEBD46D3F3BB8A2A73513F5EB79DA66190EB085FFA9F492F375A97D860EB4"),
    _h("520883949DFDBC42D3AD198640688A6FE13F41349554B49ACC31DCCD884539816F5EB4AC8FB1F1A6"),
    _h("43BD7E9AFB53D8B85289BCC48EE5BFE6F20137D10A087EB6E7871E2A10A599C710AF8D0D39E20611"),
    _h("14FDD05545EC1CC8AB4093247F77275E0743FFED117182EAA9C77877AAAC6AC7D35245D1692E8EE1"),
    _h("D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311"),
    29,  # Trifork's patched OpenSSL announces brainpoolP320r1 as TLS curve 29
)
P256 = Curve(
    _h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
    _h("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
    _h("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
    _h("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    _h("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    _h("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
    23,
)
P256_OID = bytes.fromhex("2a8648ce3d030107")

# ---------------------------------------------------------------- DER


def _der(tag, *parts):
    c = b"".join(parts)
    n = len(c)
    if n < 0x80:
        return bytes([tag, n]) + c
    nb = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(nb)]) + nb + c


def _int(v):
    return _der(2, v.to_bytes(v.bit_length() // 8 + 1, "big"))


def _children(b):
    """[(tag, content, full)] of a DER blob."""
    out, i = [], 0
    while i < len(b):
        tag, n, j = b[i], b[i + 1], i + 2
        if n & 0x80:
            n, j = int.from_bytes(b[j : j + (n & 0x7F)], "big"), j + (n & 0x7F)
        out.append((tag, b[j : j + n], b[i : j + n]))
        i = j + n
    return out


def _spki(cert):
    """Raw SubjectPublicKeyInfo of a certificate."""
    tbs = _children(_children(_children(cert)[0][1])[0][1])
    if tbs[0][0] == 0xA0:
        tbs = tbs[1:]
    return tbs[5][2]


def _pubkey(cert):
    spki = _spki(cert)
    curve = P256 if P256_OID in spki else BP320
    return curve, curve.decode(_children(_children(spki)[0][1])[1][1][1:])


def peer_id(cert):
    """MDG device ID: the certificate's SubjectKeyIdentifier as aa:bb:.. hex."""
    i = cert.find(bytes.fromhex("0603551d0e"))
    if i < 0:
        raise LinkError("certificate has no SubjectKeyIdentifier")
    ski = _children(_children(cert[i + 5 :])[0][1])[0][1]
    return ":".join(f"{c:02x}" for c in ski)


# Explicit brainpoolP320r1 parameters, encoded exactly as in the app's certificates.
BP320_PARAMS = bytes.fromhex(
    "30820110020101303406072a8648ce3d0101022900d35e472036bc4fb7e13c785ed201e065f98fcfa6"
    "f6f40def4f92b9ec7893ec28fcd412b1f1b32e27305404283ee30b568fbab0f883ccebd46d3f3bb8a2"
    "a73513f5eb79da66190eb085ffa9f492f375a97d860eb40428520883949dfdbc42d3ad198640688a6f"
    "e13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a604510443bd7e9afb53d8b85289bcc48ee5"
    "bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f7727"
    "5e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1022900d35e472036bc4fb7e13c785ed2"
    "01e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311020101"
)
ECDSA_SHA256 = _der(0x30, bytes.fromhex("06082a8648ce3d040302"))


def new_identity():
    """Key + self-signed certificate shaped like the original app's (the relay expects that)."""
    d = BP320.scalar()
    pub = BP320.encode(BP320.mul(BP320.g, d))
    name = _der(
        0x30,
        *(
            _der(0x31, _der(0x30, _der(6, bytes.fromhex(oid)), _der(0x13, val.encode())))
            for oid, val in (("550406", "DK"), ("55040a", "Trifork"), ("550403", "localhost"))
        ),
    )
    ski = hashlib.sha1(pub).digest()
    now = int(time.time())
    validity = _der(
        0x30,
        _der(0x17, time.strftime("%y%m%d%H%M%SZ", time.gmtime(now)).encode()),
        _der(0x18, time.strftime("%Y%m%d%H%M%SZ", time.gmtime(now + 2_000_000_000)).encode()),
    )
    ext = lambda oid, val, *crit: _der(0x30, _der(6, bytes.fromhex(oid)), *crit, _der(4, val))  # noqa: E731
    tbs = _der(
        0x30,
        _der(0xA0, _int(2)),
        _int(1),
        ECDSA_SHA256,
        name,
        validity,
        name,
        _der(0x30, _der(0x30, bytes.fromhex("06072a8648ce3d0201"), BP320_PARAMS), _der(3, b"\0" + pub)),
        _der(0xA3, _der(0x30,
            ext("551d0e", _der(4, ski)),
            ext("551d23", _der(0x30, _der(0x80, ski))),
            ext("551d13", _der(0x30), _der(1, b"\xff")),
        )),
    )
    sig = BP320.sign(d, hashlib.sha256(tbs).digest())
    cert = _der(0x30, tbs, ECDSA_SHA256, _der(3, b"\0" + sig))
    return {"key": f"{d:x}", "cert": base64.b64encode(cert).decode()}


# ---------------------------------------------------------------- TLS 1.2


def _prf(secret, label, seed, n):
    seed, out, a = label + seed, b"", label + seed
    while len(out) < n:
        a = hmac.new(secret, a, hashlib.sha384).digest()
        out += hmac.new(secret, a + seed, hashlib.sha384).digest()
    return out[:n]


class TLS:
    """Minimal TLS 1.2 client: ECDHE-ECDSA-AES256-GCM-SHA384 with a client certificate.

    Needed because the peers announce brainpoolP320r1 as curve id 29 (X25519 elsewhere).
    """

    def __init__(self, sock, cert, key):
        self.sock, self.buf, self.hs = sock, b"", b""
        self.enc = self.dec = None
        self.wseq = self.rseq = 0
        self._handshake(cert, key)

    def _read_exact(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise LinkError("connection closed")
            data += chunk
        return data

    def _record(self):
        typ, _, n = struct.unpack(">BHH", self._read_exact(5))
        body = self._read_exact(n)
        if self.dec:
            aad = struct.pack(">QBHH", self.rseq, typ, 0x0303, n - 24)
            body = self.dec[0].decrypt(self.dec[1] + body[:8], body[8:], aad)
            self.rseq += 1
        if typ == 21:
            raise LinkError(f"TLS alert {body[1]}")
        return typ, body

    def _write(self, typ, data):
        for i in range(0, max(len(data), 1), 16384):
            frag = data[i : i + 16384]
            if self.enc:
                nonce = struct.pack(">Q", self.wseq)
                aad = struct.pack(">QBHH", self.wseq, typ, 0x0303, len(frag))
                frag = nonce + self.enc[0].encrypt(self.enc[1] + nonce, frag, aad)
                self.wseq += 1
            self.sock.sendall(struct.pack(">BHH", typ, 0x0303, len(frag)) + frag)

    def _hs_send(self, typ, body):
        msg = bytes([typ]) + len(body).to_bytes(3, "big") + body
        self.hs += msg
        self._write(22, msg)

    def _hs_recv(self):
        while len(self.buf) < 4 or len(self.buf) < 4 + int.from_bytes(self.buf[1:4], "big"):
            typ, body = self._record()
            if typ != 22:
                raise LinkError("unexpected TLS record")
            self.buf += body
        n = 4 + int.from_bytes(self.buf[1:4], "big")
        msg, self.buf = self.buf[:n], self.buf[n:]
        self.hs += msg
        return msg[0], msg[4:]

    def _handshake(self, cert, key):
        cr = secrets.token_bytes(32)
        ext = b"".join(
            struct.pack(">HH", t, len(v)) + v
            for t, v in (
                (10, bytes.fromhex("0004001d0017")),  # groups: 29 (brainpoolP320r1 here), P-256
                (11, b"\x01\x00"),
                (13, bytes.fromhex("00080403050306030203")),  # ECDSA + SHA256/384/512/1
                (0xFF01, b"\x00"),
            )
        )
        self._hs_send(1, b"\x03\x03" + cr + b"\x00\x00\x02\xc0\x2c\x01\x00" + struct.pack(">H", len(ext)) + ext)
        certs, ske, sr, requested = [], None, None, False
        while True:
            typ, b = self._hs_recv()
            if typ == 2:
                sr = b[2:34]
                if b[35 + b[34] : 37 + b[34]] != b"\xc0\x2c":
                    raise LinkError("unexpected TLS cipher")
            elif typ == 11:
                i = 3
                while i < 3 + int.from_bytes(b[:3], "big"):
                    n = int.from_bytes(b[i : i + 3], "big")
                    certs.append(b[i + 3 : i + 3 + n])
                    i += 3 + n
            elif typ == 12:
                ske = b
            elif typ == 13:
                requested = True
            elif typ == 14:
                break
        curve = {c.tls_id: c for c in (BP320, P256)}[int.from_bytes(ske[1:3], "big")]
        plen = ske[3]
        params, server_pub = ske[: 4 + plen], curve.decode(ske[4 : 4 + plen])
        hash_alg = {2: hashlib.sha1, 4: hashlib.sha256, 5: hashlib.sha384, 6: hashlib.sha512}[ske[4 + plen]]
        sig = ske[8 + plen : 8 + plen + int.from_bytes(ske[6 + plen : 8 + plen], "big")]
        cert_curve, cert_pub = _pubkey(certs[0])
        if not cert_curve.verify(cert_pub, hash_alg(cr + sr + params).digest(), sig):
            raise LinkError("bad TLS server signature")
        self.peer_cert = certs[0]

        if requested:
            self._hs_send(11, (len(cert) + 3).to_bytes(3, "big") + len(cert).to_bytes(3, "big") + cert)
        eph = curve.scalar()
        pub = curve.encode(curve.mul(curve.g, eph))
        self._hs_send(16, bytes([len(pub)]) + pub)
        premaster = curve.mul(server_pub, eph)[0].to_bytes(curve.size, "big")
        master = _prf(premaster, b"master secret", cr + sr, 48)
        if requested:
            sig = BP320.sign(key, hashlib.sha256(self.hs).digest())
            self._hs_send(15, b"\x04\x03" + struct.pack(">H", len(sig)) + sig)
        kb = _prf(master, b"key expansion", sr + cr, 72)
        self._write(20, b"\x01")
        self.enc = (AESGCM(kb[:32]), kb[64:68])
        self._hs_send(20, _prf(master, b"client finished", hashlib.sha384(self.hs).digest(), 12))
        if self._record()[0] != 20:
            raise LinkError("expected ChangeCipherSpec")
        self.dec = (AESGCM(kb[32:64]), kb[68:72])
        expected = _prf(master, b"server finished", hashlib.sha384(self.hs).digest(), 12)
        if self._hs_recv() != (20, expected):
            raise LinkError("bad TLS Finished")

    def read(self, n):
        while len(self.buf) < n:
            typ, body = self._record()
            if typ == 23:
                self.buf += body
        data, self.buf = self.buf[:n], self.buf[n:]
        return data

    def write(self, data):
        self._write(23, data)


# ---------------------------------------------------------------- framing + protobuf


def _send(io, data):
    (io.write if isinstance(io, TLS) else io.sendall)(struct.pack(">H", len(data)) + data)


def _recv(io):
    read = io.read if isinstance(io, TLS) else lambda n: _sock_read(io, n)
    return read(struct.unpack(">H", read(2))[0])


def _sock_read(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise LinkError("connection closed")
        data += chunk
    return data


def _varint(v):
    out = b""
    while v > 0x7F:
        out += bytes([v & 0x7F | 0x80])
        v >>= 7
    return out + bytes([v])


def _pv(field, v):
    return _varint(field << 3) + _varint(v)


def _pb(field, b):
    return _varint(field << 3 | 2) + _varint(len(b)) + b


def _pf32(field, v):
    return _varint(field << 3 | 5) + struct.pack("<I", v)


def _parse(b):
    """{field: value} of a protobuf message (last occurrence wins)."""
    out, i = {}, 0
    while i < len(b):
        tag = shift = 0
        while True:
            tag |= (b[i] & 0x7F) << shift
            shift, i = shift + 7, i + 1
            if not b[i - 1] & 0x80:
                break
        field, wire = tag >> 3, tag & 7
        if wire == 5:
            out[field], i = struct.unpack("<I", b[i : i + 4])[0], i + 4
            continue
        v = shift = 0
        while True:
            v |= (b[i] & 0x7F) << shift
            shift, i = shift + 7, i + 1
            if not b[i - 1] & 0x80:
                break
        if wire == 2:
            out[field], i = b[i : i + v], i + v
        else:
            out[field] = v
    return out


def _version(magic):
    return _pf32(1, magic) + _pv(2, 1) + _pv(3, 0)


# ---------------------------------------------------------------- relay


def _connect(host, port):
    sock = socket.create_connection((host, port), TIMEOUT)
    sock.settimeout(TIMEOUT)
    return sock


class _Session:
    """Relay control connection plus one routed, end-to-end TLS channel to the panel."""

    def __init__(self, cert, key, peer=None, pair_id=None):
        self.socks = []
        try:
            self._open(cert, key, peer, pair_id)
        except (OSError, KeyError, IndexError, ValueError) as err:
            self.close()
            raise LinkError(f"relay: {err!r}") from err
        except LinkError:
            self.close()
            raise

    def _open(self, cert, key, peer, pair_id):
        for host in RELAYS:
            try:
                self.socks.append(_connect(host, 443))
                break
            except OSError:
                continue
        else:
            raise LinkError("cannot reach the Danfoss/Trifork relay")
        self.ctl, self.req = TLS(self.socks[0], cert, key), 0
        props = (("app.package.name", "com.danfoss.linkapp"), ("app.version.name", "Android-1.3.10"))
        _send(self.ctl, b"\x01" + _version(CTL_MAGIC) + b"".join(_pb(4, _pb(1, k.encode()) + _pb(2, v.encode())) for k, v in props))
        if pair_id:
            reply = self._request(32, _pb(2, pair_id.encode()), 33)
        else:
            self._request(20, _pb(2, peer.encode()), 21)  # whitelist the panel
            reply = self._request(10, _pb(2, peer.encode()) + _pb(3, b"cc_json"), 11)
        if reply.get(2):
            raise LinkError("panel not available (offline, not paired, or code expired)")
        routing = _parse(reply[3])
        router = _parse(routing[4])
        self.socks.append(sock := _connect(router[1].decode(), router[2]))
        _send(sock, b"\x00" + _version(ROUTING_MAGIC) + _pb(4, routing[5]) + _pb(5, b"tlsv1_2"))
        while (msg := _recv(sock))[0] != 2:  # 1 = please hold, 2 = go ahead
            if msg[0] != 1:
                raise LinkError(f"routing error {_parse(msg[1:]).get(1)}")
        self.panel = TLS(sock, cert, key)

    def _request(self, typ, body, reply_typ):
        self.req += 1
        _send(self.ctl, bytes([typ]) + _pv(1, self.req) + body)
        while True:
            msg = _recv(self.ctl)
            fields = _parse(msg[1:])
            if msg[0] == 2:
                raise LinkError(f"relay said bye ({fields.get(1)})")
            if msg[0] == 4:
                _send(self.ctl, b"\x05" + _pv(1, fields[1]))
            elif msg[0] == reply_typ and fields.get(1) == self.req:
                return fields

    def close(self):
        for sock in self.socks:
            sock.close()


def _pem(spki):
    b64 = base64.b64encode(spki).decode()
    return ("-----BEGIN PUBLIC KEY-----\n" + "".join(b64[i : i + 64] + "\n" for i in range(0, len(b64), 64)) + "-----END PUBLIC KEY-----\n").encode()


def pair(code, name="Home Assistant"):
    """Pair with the panel using the 9-digit code it shows; returns the config entry data."""
    code = "".join(c for c in code if c.isdigit())
    if len(code) < 6:
        raise LinkError("pairing code too short")
    ident = new_identity()
    cert, key = base64.b64decode(ident["cert"]), int(ident["key"], 16)
    session = _Session(cert, key, pair_id=code[:-5])
    try:
        ch, c = session.panel, BP320
        pi = b"".join(struct.pack(">H", len(p)) + p for p in (code[-5:].encode(), _pem(_spki(ch.peer_cert)), _pem(_spki(cert)))) + b"\xff"

        def exchange(typ, body):
            _send(ch, bytes([typ]) + body)
            msg = _recv(ch)
            if msg[0] != typ:
                raise LinkError("pairing rejected (wrong code?)")
            return _parse(msg[1:])

        _send(ch, b"\x01" + _version(PACE_MAGIC))  # client hello; the panel answers with server hello (2)
        hello = _parse(_recv(ch)[1:])
        kpi = hashlib.pbkdf2_hmac("sha256", pi, hello[3], 1024, 32)[:16]
        # Key zero-padded to AES-256 and an all-zero IV, exactly like the app's luacrypto calls.
        nonce = Cipher(algorithms.AES(kpi + bytes(16)), modes.CBC(bytes(16))).decryptor().update(hello[5])
        s = int.from_bytes(nonce[: c.size], "big")
        x = c.scalar()
        Y = c.decode(exchange(3, _pb(1, c.encode(c.mul(c.g, x))))[1])
        g2 = c.add(c.mul(c.g, s), c.mul(Y, x))
        x2 = c.scalar()
        own = c.mul(g2, x2)
        peer = c.decode(exchange(4, _pb(1, c.encode(own)))[1])
        kmac = hashlib.sha256(c.encode(c.mul(peer, x2))).digest()
        token = lambda P: hmac.new(kmac, c.encode(P), hashlib.sha256).hexdigest().encode()  # noqa: E731
        if exchange(5, _pb(1, token(peer)))[1] != token(own):
            raise LinkError("pairing failed: wrong code")
        exchange(6, _pb(1, name.encode()))
        panel_cert = ch.peer_cert
    except (KeyError, IndexError, ValueError) as err:
        raise LinkError(f"pairing protocol error: {err!r}") from err
    finally:
        session.close()
    return {**ident, "panel_cert": base64.b64encode(panel_cert).decode(), "panel_id": peer_id(panel_cert)}


def request(entry, method, uri, body=None):
    """One request to the panel's REST API (e.g. GET /api/world); returns the JSON content."""
    cert = base64.b64decode(entry["cert"])
    session = _Session(cert, int(entry["key"], 16), peer=entry["panel_id"])
    try:
        if session.panel.peer_cert != base64.b64decode(entry["panel_cert"]):
            raise LinkError("panel certificate differs from the one pinned at pairing")
        data = {"method": method, "uri": uri, "headers": ["Accept: application/json; charset=utf-8"]}
        if body is not None:
            data["content"] = body
        _send(session.panel, json.dumps({"id": 1, "data": {"type": "JsonWebRequest", "data": data}}).encode())
        reply = json.loads(_recv(session.panel).replace(b'"content":}', b'"content":null}'))["data"]["data"]
    except (OSError, KeyError, ValueError) as err:
        raise LinkError(f"panel request failed: {err!r}") from err
    finally:
        session.close()
    if not 200 <= reply["status"] < 300:
        raise LinkError(f"{method} {uri}: HTTP {reply['status']}")
    return reply.get("content")
