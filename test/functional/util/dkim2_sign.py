#!/usr/bin/env python3
"""
Produce DKIM2 signed messages for the functional tests.

This is an independent, deliberately straightforward implementation of the
signing side of draft-ietf-dkim-dkim2-spec-09: it shares no code with the
verifier in rspamd, so the tests check the verifier against a second reading
of the specification. Signatures have timestamps, hence the messages are
generated when the tests run and are not stored in the repository.

Only the Python standard library and the `openssl` command line tool are used.

Usage: dkim2_sign.py --rsa-key FILE --ed-key FILE SCENARIO OUTPUT
"""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
import time

UNSIGNED = {
    "apparently-to", "arc-authentication-results", "arc-message-signature",
    "arc-seal", "authentication-results", "delivered-to", "dkim-signature",
    "dl-expansion-history", "original-recipient", "received", "return-path",
    "sio-label-history", "x400-received", "x400-trace",
    "message-instance", "dkim2-signature",
}


def b64(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.b64encode(data).decode()


def is_unsigned(name):
    name = name.lower()
    return name in UNSIGNED or name.startswith("x-") or name.startswith("received-")


class Message:
    """Header fields from the top to the bottom, and the body as CRLF lines"""

    def __init__(self, headers, body_lines):
        self.headers = list(headers)
        self.body = list(body_lines)

    def copy(self):
        return Message(self.headers, self.body)

    def instances(self, name):
        """Unfolded values of a header field, bottom-up (number 1 goes first)"""
        return [v.replace("\r\n", "") for n, v in reversed(self.headers)
                if n.lower() == name.lower()]

    def signed_names(self):
        return sorted({n.lower() for n, _ in self.headers if not is_unsigned(n)})

    def header_hash(self, alg):
        out = b""
        for name in self.signed_names():
            for value in self.instances(name):
                collapsed = " ".join(value.replace("\t", " ").split(" "))
                collapsed = " ".join(part for part in collapsed.split(" ") if part)
                out += name.encode() + b":" + collapsed.encode("utf-8", "surrogateescape") + b"\r\n"
        return hashlib.new(alg, out).digest()

    def body_hash(self, alg):
        lines = list(self.body)
        while lines and lines[-1] == "":
            lines.pop()
        data = "".join(line + "\r\n" for line in lines) if lines else "\r\n"
        return hashlib.new(alg, data.encode("utf-8", "surrogateescape")).digest()

    def hash_set(self, alg):
        return "%s:%s:%s" % (alg, b64(self.header_hash(alg)), b64(self.body_hash(alg)))

    def render(self):
        out = "".join("%s: %s\r\n" % (n, v) for n, v in self.headers)
        return (out + "\r\n" + "".join(line + "\r\n" for line in self.body)).encode(
            "utf-8", "surrogateescape")


def make_recipe(old, new):
    """Recipes that recreate `old` from `new` (Section 5)"""
    recipe = {}
    headers = {}

    for name in sorted(set(old.signed_names()) | set(new.signed_names())):
        was, now = old.instances(name), new.instances(name)
        if was == now:
            continue
        steps = []
        # Keep the common bottom instances, replace the rest
        common = 0
        while common < min(len(was), len(now)) and was[common] == now[common]:
            common += 1
        if common:
            steps.append({"c": [1, common]})
        if was[common:]:
            steps.append({"d": was[common:]})
        headers[name] = steps

    if headers:
        recipe["h"] = headers

    if old.body != new.body:
        steps = []
        common = 0
        while common < min(len(old.body), len(new.body)) and old.body[common] == new.body[common]:
            common += 1
        if common:
            steps.append({"c": [1, common]})
        if old.body[common:]:
            steps.append({"d": old.body[common:]})
        recipe["b"] = steps

    return recipe


def canon_sig(name, value):
    """Section 12.8: lowercase name, no whitespace at all"""
    stripped = "".join(value.replace("\r\n", "").split())
    return (name.lower() + ":" + stripped + "\r\n").encode()


class Signer:
    def __init__(self, rsa_key, ed_key):
        self.keys = {"rsa-sha256": rsa_key, "ed25519-sha256": ed_key}

    def sign(self, alg, data):
        with tempfile.NamedTemporaryFile() as tmp:
            if alg == "rsa-sha256":
                tmp.write(data)
                tmp.flush()
                cmd = ["openssl", "dgst", "-sha256", "-sign", self.keys[alg], tmp.name]
            elif alg == "ed25519-sha256":
                # PureEdDSA over the SHA-256 digest of the input
                tmp.write(hashlib.sha256(data).digest())
                tmp.flush()
                cmd = ["openssl", "pkeyutl", "-sign", "-inkey", self.keys[alg],
                       "-rawin", "-in", tmp.name]
            else:
                # An algorithm that nobody implements
                return b"\x00" * 64
            return subprocess.run(cmd, check=True, capture_output=True).stdout


class Chain:
    """A message on its way: adds Message-Instance and DKIM2-Signature fields"""

    def __init__(self, signer, msg, now=None):
        self.signer = signer
        self.msg = msg
        self.now = int(time.time()) if now is None else now
        self.mi = []    # values of the Message-Instance fields, m=1 first
        self.sigs = []  # values of the DKIM2-Signature fields, i=1 first
        self.last = None

    def add_instance(self, recipe=None, hashes=None, raw_recipe=None):
        """Record the current message as a new instance"""
        m = len(self.mi) + 1
        if recipe is None and raw_recipe is None and self.last is not None:
            recipe = make_recipe(self.last, self.msg)
        value = "m=%d; h=%s" % (m, hashes or self.msg.hash_set("sha256"))
        if raw_recipe is not None:
            value += "; r=" + b64(raw_recipe)
        elif recipe:
            value += "; r=" + b64(json.dumps(recipe, separators=(",", ":")))
        self.mi.append(value)
        self.last = self.msg.copy()

    def add_signature(self, domain, mf=None, rt=None, nd=None, sigs=None, flags=None,
                      t=None, m=None, corrupt=False):
        """
        `sigs` is a list of groups (joined with `|`), each a list of
        (selector, algorithm) pairs (joined with `,`)
        """
        i = len(self.sigs) + 1
        sigs = sigs or [[("rsa", "rsa-sha256")]]
        tags = ["i=%d" % i, "m=%d" % (m or len(self.mi)),
                "t=%d" % (self.now if t is None else t), "d=" + domain]
        if nd is not None:
            tags.append("nd=" + nd)
        else:
            tags.append("mf=" + b64(mf))
            tags.append("rt=" + ",".join(b64(r) for r in rt))
        if flags:
            tags.append("f=" + ",".join(flags))

        def s_tag(values):
            return "s=" + " | ".join(
                ", ".join("%s:%s:%s" % (sel, alg, values.get((sel, alg), ""))
                          for sel, alg in group)
                for group in sigs)

        unsigned = "; ".join(tags + [s_tag({})])
        data = b"".join(canon_sig("Message-Instance", v) for v in self.mi[:m or len(self.mi)])
        data += b"".join(canon_sig("DKIM2-Signature", v) for v in self.sigs)
        data += canon_sig("DKIM2-Signature", unsigned)

        values = {}
        for group in sigs:
            for sel, alg in group:
                raw = self.signer.sign(alg, data)
                if corrupt:
                    raw = bytes([raw[0] ^ 0xff]) + raw[1:]
                values[(sel, alg)] = b64(raw)

        self.sigs.append("; ".join(tags + [s_tag(values)]))

    def render(self):
        out = self.msg.copy()
        # Trace fields go on top, the newest first
        fields = [("Message-Instance", v) for v in self.mi] + \
                 [("DKIM2-Signature", fold(v)) for v in self.sigs]
        out.headers = list(reversed(fields)) + out.headers
        return out.render()


def fold(value):
    """Fold a long tag list at the semicolons"""
    return value.replace("; ", ";\r\n\t")


def original():
    return Message([
        ("Received", "from localhost by mx.example.com; Mon, 1 Jan 2024 00:00:00 +0000"),
        ("From", "Alice Example <alice@example.com>"),
        ("To", "list@example.net"),
        ("Subject", "DKIM2   test\r\n message"),
        ("Date", "Mon, 1 Jan 2024 00:00:00 +0000"),
        ("Message-ID", "<dkim2-test@example.com>"),
        ("X-Mailer", "not signed"),
        ("MIME-Version", "1.0"),
        ("Content-Type", "text/plain; charset=utf-8"),
    ], ["Hello,", "", "this is a test of DKIM2.", " ", "-- ", "Alice", "", ""])


def originate(signer, **kwargs):
    chain = Chain(signer, original(), now=kwargs.pop("now", None))
    chain.add_instance()
    args = dict(domain="example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
    args.update(kwargs)
    chain.add_signature(**args)
    return chain


def list_modify(chain):
    """What a mailing list does: a subject tag and a footer"""
    msg = chain.msg
    msg.headers = [(n, "[list] DKIM2 test message" if n == "Subject" else v)
                   for n, v in msg.headers]
    msg.headers.insert(0, ("List-Id", "<list.example.net>"))
    msg.headers.insert(0, ("Received", "from mx.example.com by mx.example.net"))
    while msg.body and msg.body[-1] == "":
        msg.body.pop()
    msg.body += ["_______________", "list footer"]


def forward(chain, **kwargs):
    list_modify(chain)
    chain.add_instance(**kwargs.pop("instance", {}))
    args = dict(domain="example.net", mf="<bounces@lists.example.net>",
                rt=["<bob@example.org>"], sigs=[[("ed", "ed25519-sha256")]],
                flags=["exploded"])
    args.update(kwargs)
    chain.add_signature(**args)
    return chain


def scenario(name, signer):
    """Returns the message; the SMTP envelope to scan it with is in the tests"""
    now = int(time.time())

    if name in ("idn_from", "idn_unsigned", "idn_foreign"):
        # An EAI message: the From has a U-label, DKIM2 itself works with A-labels
        chain = Chain(signer, original())
        chain.msg.headers = [(n, "Arnt <arnt@gr\u00e5.org>" if n == "From" else v)
                             for n, v in chain.msg.headers]
        if name == "idn_unsigned":
            return chain.msg.render()
        chain.add_instance()
        chain.add_signature("xn--gr-zia.org" if name == "idn_from" else "example.com",
                            mf="<bounce@xn--gr-zia.org>" if name == "idn_from" else "<bounce@example.com>",
                            rt=["<list@example.net>"])
        return chain.render()
    if name == "unsigned":
        # For the signing tests: Rspamd is the Originator
        return original().render()
    if name == "simple":
        return originate(signer).render()
    if name == "tampered_body":
        chain = originate(signer)
        chain.msg.body[0] = "Hallo,"
        return chain.render()
    if name == "tampered_header":
        chain = originate(signer)
        chain.msg.headers.insert(1, ("Reply-To", "mallory@example.org"))
        return chain.render()
    if name == "unsigned_header":
        # Fields that are not signed may come and go
        chain = originate(signer)
        chain.msg.headers.insert(0, ("X-Spam-Flag", "NO"))
        chain.msg.headers.insert(0, ("Received-SPF", "pass"))
        chain.msg.headers.insert(0, ("Authentication-Results", "mx.example.net; none"))
        return chain.render()
    if name == "hidden_after_cr":
        # Text that a tolerant header parser cuts off at a bare CR
        chain = originate(signer)
        return chain.render().replace(b"Message-ID: <dkim2-test@example.com>\r\n",
                                      b"Message-ID: <dkim2-test@example.com>\r- pay now\r\n")
    if name == "garbage_line":
        # Not a header field: a tolerant parser skips it
        chain = originate(signer)
        return chain.render().replace(b"MIME-Version: 1.0\r\n",
                                      b"MIME-Version: 1.0\r\nthis is not a header field\r\n")
    if name == "odd_header_name":
        # A valid field name that a tolerant parser does not take for one
        chain = Chain(signer, original())
        chain.msg.headers.insert(3, ("1st-Header", "is signed as well"))
        chain.add_instance()
        chain.add_signature("example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
        return chain.render()
    if name == "odd_header_added":
        chain = originate(signer)
        chain.msg.headers.insert(3, ("1st-Header", "added in transit"))
        return chain.render()
    if name == "from_confusion":
        # One address for a tolerant parser, and it is the attacker's one
        chain = Chain(signer, original())
        chain.msg.headers = [(n, "ceo@example.org x@example.com" if n == "From" else v)
                             for n, v in chain.msg.headers]
        chain.add_instance()
        chain.add_signature("example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
        return chain.render()
    if name == "bad_signature":
        return originate(signer, corrupt=True).render()
    if name == "expired":
        return originate(signer, t=now - 15 * 86400).render()
    if name == "future":
        return originate(signer, t=now + 2 * 86400).render()
    if name == "hybrid":
        # Both signatures of the group are required
        return originate(signer, sigs=[[("rsa", "rsa-sha256"), ("ed", "ed25519-sha256")]]).render()
    if name == "alternative":
        # An algorithm from the future with a fallback
        return originate(signer, sigs=[[("pq", "falcon512")], [("rsa", "rsa-sha256")]]).render()
    if name == "unknown_alg":
        return originate(signer, sigs=[[("pq", "falcon512")]]).render()
    if name == "hybrid_unknown":
        return originate(signer, sigs=[[("rsa", "rsa-sha256"), ("pq", "falcon512")]]).render()
    if name == "pkcs1_key":
        return originate(signer, sigs=[[("pkcs1", "rsa-sha256")]]).render()
    if name == "revoked":
        return originate(signer, sigs=[[("revoked", "rsa-sha256")]]).render()
    if name == "nokey":
        return originate(signer, sigs=[[("absent", "rsa-sha256")]]).render()
    if name == "two_records":
        return originate(signer, sigs=[[("two", "rsa-sha256")]]).render()
    if name == "key_mismatch":
        # An Ed25519 key record for an RSA signature
        return originate(signer, sigs=[[("ed", "rsa-sha256")]]).render()
    if name == "sha512":
        chain = Chain(signer, original())
        chain.add_instance(hashes=chain.msg.hash_set("sha512"))
        chain.add_signature("example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
        return chain.render()
    if name == "hash_alternative":
        chain = Chain(signer, original())
        chain.add_instance(hashes="sha3:AAAA:AAAA | " + chain.msg.hash_set("sha256"))
        chain.add_signature("example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
        return chain.render()
    if name == "subdomain_from":
        # mail.example.com signs for a From at example.com, which allows it
        return originate(signer, domain="mail.example.com",
                         mf="<bounce@mail.example.com>").render()
    if name == "strict_from":
        # A From at strict.example, which forbids its subdomains to sign for it
        chain = Chain(signer, original())
        chain.msg.headers = [(n, "alice@strict.example" if n == "From" else v)
                             for n, v in chain.msg.headers]
        chain.add_instance()
        chain.add_signature("mail.strict.example", mf="<bounce@mail.strict.example>",
                            rt=["<list@example.net>"])
        return chain.render()
    if name == "foreign_from":
        chain = Chain(signer, original())
        chain.msg.headers = [(n, "ceo@example.org" if n == "From" else v)
                             for n, v in chain.msg.headers]
        chain.add_instance()
        chain.add_signature("example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
        return chain.render()
    if name == "two_from":
        chain = Chain(signer, original())
        chain.msg.headers = [(n, "alice@example.com, bob@example.com" if n == "From" else v)
                             for n, v in chain.msg.headers]
        chain.add_instance()
        chain.add_signature("example.com", mf="<bounce@example.com>", rt=["<list@example.net>"])
        return chain.render()
    if name == "forwarded":
        return forward(originate(signer)).render()
    if name == "forwarded_unchanged":
        # A forwarder that changes nothing adds only a signature
        chain = originate(signer)
        chain.add_signature("example.net", mf="<bounces@example.net>", rt=["<bob@example.org>"],
                            sigs=[[("ed", "ed25519-sha256")]])
        return chain.render()
    if name == "undeclared_change":
        # The recipe does not mention the new footer
        chain = originate(signer)
        return forward(chain, instance=dict(recipe={"h": {
            "subject": [{"d": ["DKIM2   test message"]}], "list-id": []}})).render()
    if name == "null_recipe":
        chain = originate(signer)
        return forward(chain, instance=dict(recipe={"h": {
            "subject": [{"d": ["DKIM2   test message"]}], "list-id": []}, "b": None})).render()
    if name == "duplicate_keys":
        # Two "b" members: which one applies depends on the JSON parser
        chain = originate(signer)
        list_modify(chain)
        good = make_recipe(chain.last, chain.msg)
        raw = json.dumps(good, separators=(",", ":"))[:-1] + ',"b":[]}'
        chain.add_instance(raw_recipe=raw)
        chain.add_signature("example.net", mf="<bounces@example.net>", rt=["<bob@example.org>"],
                            sigs=[[("ed", "ed25519-sha256")]])
        return chain.render()
    if name == "replay":
        # example.org was never a recipient of the original message
        chain = originate(signer)
        chain.add_signature("example.org", mf="<spam@example.org>", rt=["<bob@example.org>"])
        return chain.render()
    if name == "from_rewrite":
        # The list takes over the From, so it has to be Authentic for the list
        chain = originate(signer)
        chain.msg.headers = [(n, "Alice via list <list@example.net>" if n == "From" else v)
                             for n, v in chain.msg.headers]
        return forward(chain).render()
    if name == "from_hijack":
        # The Reviser puts a From of a domain it cannot sign for
        chain = originate(signer)
        chain.msg.headers = [(n, "ceo@example.org" if n == "From" else v)
                             for n, v in chain.msg.headers]
        return forward(chain).render()
    if name == "imaginary_hop":
        # Received for example.net, sent on from example.org
        chain = originate(signer)
        chain.add_signature("example.net", nd="example.org", sigs=[[("ed", "ed25519-sha256")]])
        chain.add_signature("example.org", mf="<fwd@example.org>", rt=["<bob@example.org>"])
        return chain.render()
    if name == "trailing_nd":
        chain = originate(signer)
        chain.add_signature("example.net", nd="example.org", sigs=[[("ed", "ed25519-sha256")]])
        return chain.render()
    if name == "bounce":
        # A DSN: the null reverse-path, signed by the domain of a recipient
        chain = Chain(signer, original())
        chain.msg.headers = [(n, "MAILER-DAEMON@example.net" if n == "From" else v)
                             for n, v in chain.msg.headers]
        chain.add_instance()
        chain.add_signature("example.net", mf="<>", rt=["<bounce@example.com>"],
                            sigs=[[("ed", "ed25519-sha256")]])
        return chain.render()
    if name == "exploded_first":
        return originate(signer, flags=["exploded"]).render()
    if name == "gap":
        chain = originate(signer)
        chain.mi[0] = chain.mi[0].replace("m=1", "m=2")
        return chain.render()
    if name == "unsigned_instance":
        # One more instance that no signature covers
        chain = originate(signer)
        list_modify(chain)
        chain.add_instance()
        return chain.render()

    raise SystemExit("unknown scenario: %s" % name)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rsa-key", required=True)
    parser.add_argument("--ed-key", required=True)
    parser.add_argument("scenario")
    parser.add_argument("output")
    args = parser.parse_args()

    data = scenario(args.scenario, Signer(args.rsa_key, args.ed_key))

    with open(args.output, "wb") as out:
        out.write(data)


if __name__ == "__main__":
    sys.exit(main())
