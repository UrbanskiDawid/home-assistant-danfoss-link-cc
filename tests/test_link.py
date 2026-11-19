"""Protocol primitives, offline."""

import base64
import hashlib

from custom_components.danfoss_link_cc import link


def test_curves():
    for c in (link.BP320, link.P256):
        assert c.decode(c.encode(c.g)) == c.g
        assert c.mul(c.g, c.n) is None


def test_ecdsa():
    c = link.BP320
    d = c.scalar()
    q = c.mul(c.g, d)
    digest = hashlib.sha256(b"danfoss").digest()
    sig = c.sign(d, digest)
    assert c.verify(q, digest, sig)
    assert not c.verify(q, hashlib.sha256(b"other").digest(), sig)


def test_identity_certificate():
    ident = link.new_identity()
    cert = base64.b64decode(ident["cert"])
    curve, pub = link._pubkey(cert)
    assert curve is link.BP320
    assert pub == curve.mul(curve.g, int(ident["key"], 16))
    # self-signed: signature over the TBS verifies with the certificate's own key
    tbs, _, sig = link._children(link._children(cert)[0][1])
    assert curve.verify(pub, hashlib.sha256(tbs[2]).digest(), sig[1][1:])
    # device ID = SHA-1 of the public key (what the relay and panel check)
    assert link.peer_id(cert) == ":".join(f"{b:02x}" for b in hashlib.sha1(curve.encode(pub)).digest())


def test_protobuf():
    msg = link._version(link.CTL_MAGIC) + link._pb(4, b"x")
    assert link._parse(msg) == {1: link.CTL_MAGIC, 2: 1, 3: 0, 4: b"x"}
