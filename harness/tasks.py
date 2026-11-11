"""The task suite: every task is a program that reads standard input and writes standard output, so the same hidden
cases score every language. The expected outputs come from Python's standard library (zlib, hashlib, base64, hmac, csv,
struct), never from code written for this project."""
import base64, csv, hashlib, hmac, io, random, struct, zlib, collections

def rnd(seed): return random.Random(seed)

def text_bytes(r, n):
    return bytes(r.choice(b"abcdefghij klmnopqrstuvwxyz\n0123456789") for _ in range(n))

# --- each task: name, group, prompt, visible(), hidden() -> list of (stdin: bytes, stdout: bytes)
TASKS = {}
def task(name, group, prompt):
    def deco(fn):
        TASKS[name] = dict(name=name, group=group, prompt=prompt, cases=fn); return fn
    return deco

@task("crc32", "pure", "Read all of standard input and print the CRC-32 (the zlib/IEEE one) of those bytes as 8 lowercase hexadecimal digits, then a newline.")
def _(r):
    def case(n): d = text_bytes(r, n); return d, b"%08x\n" % (zlib.crc32(d) & 0xffffffff)
    return [case(n) for n in [0, 1, 13, 255, 1000, 4096, 10000]]

@task("sha256", "pure", "Read all of standard input and print the SHA-256 digest of those bytes as 64 lowercase hexadecimal digits, then a newline.")
def _(r):
    def case(n): d = text_bytes(r, n); return d, hashlib.sha256(d).hexdigest().encode() + b"\n"
    return [case(n) for n in [0, 3, 55, 56, 64, 100, 1000, 5000]]

@task("base64", "pure", "Read all of standard input and print its standard Base64 encoding (RFC 4648, with '=' padding, no line breaks), then a newline.")
def _(r):
    def case(n): d = bytes(r.randrange(256) for _ in range(n)); return d, base64.b64encode(d) + b"\n"
    return [case(n) for n in [0, 1, 2, 3, 4, 100, 1001]]

@task("sort_numbers", "pure", "Standard input holds one decimal integer per line (each fits in 64 bits, may be negative). Print them sorted in increasing order, one per line.")
def _(r):
    def case(n):
        xs = [r.randrange(-10**12, 10**12) for _ in range(n)]
        return ("".join(f"{x}\n" for x in xs)).encode(), ("".join(f"{x}\n" for x in sorted(xs))).encode()
    return [case(n) for n in [0, 1, 2, 10, 100, 1000, 3000]]

@task("word_freq", "pure", "Standard input is text. Words are maximal runs of lowercase letters a-z; every other byte separates words. Print the 5 most frequent words, most frequent first, ties broken alphabetically, as `word count` per line. Print fewer lines if there are fewer than 5 distinct words.")
def _(r):
    vocab = ["a", "ab", "cab", "dog", "egg", "fig", "gum", "hat", "ink", "jam", "kid"]
    def case(n):
        words = [r.choice(vocab) for _ in range(n)]
        seps = [r.choice([" ", "\n", ", ", "7 "]) for _ in words]
        text = "".join(w + s for w, s in zip(words, seps)).encode()
        c = collections.Counter(words)
        top = sorted(c.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
        return text, "".join(f"{w} {k}\n" for w, k in top).encode()
    return [case(n) for n in [0, 1, 7, 50, 500, 2000]]

@task("hmac_sha256", "pure", "The first line of standard input is the key, the second line is the message (neither includes its newline). Print HMAC-SHA-256 of the message under the key as 64 lowercase hexadecimal digits, then a newline.")
def _(r):
    def case(kn, mn):
        k = bytes(r.choice(b"abcdefghijklmnop") for _ in range(kn)); m = bytes(r.choice(b"abcdefghijklmnop QRS") for _ in range(mn))
        return k + b"\n" + m + b"\n", hmac.new(k, m, hashlib.sha256).hexdigest().encode() + b"\n"
    return [case(a, b) for a, b in [(1, 0), (10, 5), (64, 20), (65, 100), (100, 300), (5, 1000)]]

@task("csv_sum", "product", "Standard input is CSV (comma-separated, RFC 4180: fields may be quoted with double quotes, a doubled quote inside is one quote, quoted fields may contain commas). The first row is a header. Print the sum of the integer column named `amount`, as a decimal integer, then a newline. Rows with an empty `amount` count as 0.")
def _(r):
    def case(n):
        names = ["id", "note", "amount", "tag"]; r.shuffle(names)
        buf = io.StringIO(); w = csv.writer(buf, lineterminator="\n"); w.writerow(names); total = 0
        for i in range(n):
            amt = r.choice(["", str(r.randrange(-500, 5000))])
            if amt: total += int(amt)
            row = {"id": str(i), "note": r.choice(["plain", "with, comma", 'has "quote"', ""]), "amount": amt, "tag": r.choice(["x", "y,z"])}
            w.writerow([row[k] for k in names])
        return buf.getvalue().encode(), f"{total}\n".encode()
    return [case(n) for n in [0, 1, 5, 30, 200]]

@task("dns_query_name", "product", "Standard input is one hexadecimal string (lowercase, no spaces, one line) holding a DNS message (RFC 1035) that contains exactly one question. Print the question's name in lowercase with labels joined by '.' (no trailing dot; print `.` for the root), then a space, then the question type as a decimal number, then a newline. Names in the question section are not compressed.")
def _(r):
    def case(name, qtype):
        labels = [l for l in name.split(".") if l]
        q = b"".join(bytes([len(l)]) + l.encode() for l in labels) + b"\x00" + struct.pack(">HH", qtype, 1)
        hdr = struct.pack(">HHHHHH", r.randrange(65536), 0x0100, 1, 0, 0, 0)
        return (hdr + q).hex().encode() + b"\n", f"{name.lower().strip('.') or '.'} {qtype}\n".encode()
    return [case(n, t) for n, t in [("example.com", 1), ("WWW.Example.ORG", 28), (".", 2), ("a.b.c.d.e.f.example.net", 15), ("x", 16), ("sub.domain.example.co.uk", 5)]]

@task("mqtt_connect_encode", "product", "Standard input is one line: a client id (1-23 letters/digits), then a space, then a keep-alive in seconds (0-65535). Print, as lowercase hexadecimal on one line, the bytes of an MQTT 3.1.1 CONNECT packet with clean session set, no will, no username or password, that client id and that keep-alive; then a newline.")
def _(r):
    def case(cid, ka):
        var = b"\x00\x04MQTT\x04\x02" + struct.pack(">H", ka) + struct.pack(">H", len(cid)) + cid.encode()
        n = len(var); rem = b""
        while True:
            b = n % 128; n //= 128
            rem += bytes([b | (128 if n else 0)])
            if not n: break
        return f"{cid} {ka}\n".encode(), (b"\x10" + rem + var).hex().encode() + b"\n"
    return [case(c, k) for c, k in [("a", 0), ("client1", 60), ("abcdefghijklmnopqrstuvw", 65535), ("Z9", 1), ("device42", 300)]]

def visible_hidden(name, seed=1234):
    t = TASKS[name]
    cases = t["cases"](rnd(seed + sum(map(ord, name))))
    return cases[:2], cases[2:]
