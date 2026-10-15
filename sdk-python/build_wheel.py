"""Deterministic wheel builder (no setuptools): python build_wheel.py -> dist/crawlcheck-<v>-py3-none-any.whl.
Same inputs give the same bytes: fixed timestamps, sorted entries, fixed permissions."""
import base64, hashlib, os, re, zipfile

V = re.search(r'^version = "([^"]+)"', open("pyproject.toml").read(), re.M).group(1)
name, tag = "crawlcheck", "py3-none-any"
info = "%s-%s.dist-info" % (name, V)
readme = open("README.md", encoding="utf-8").read()
# Project-URL lines from pyproject [project.urls], so the package page links the public source (PyPI reads the wheel, not pyproject).
urls = "".join("Project-URL: %s, %s\n" % (k, v) for k, v in re.findall(r'(\w+) = "([^"]+)"', re.search(r'^urls = \{([^}]*)\}', open("pyproject.toml").read(), re.M).group(1)))
files = {}
for f in sorted(os.listdir(name)):
    if f.endswith(".py"):
        files[name + "/" + f] = open(os.path.join(name, f), "rb").read()
files[info + "/METADATA"] = ("Metadata-Version: 2.1\nName: %s\nVersion: %s\nSummary: CrawlCheck client: resolve a domain, get a signed decision for an agent action, verify CrawlCheck evidence offline. No dependencies.\n"
    "Home-page: https://crawlcheck.io/sdk\nAuthor: VSNARY\nLicense: MIT\nRequires-Python: >=3.8\n%sDescription-Content-Type: text/markdown\n\n%s" % (name, V, urls, readme)).encode()
files[info + "/WHEEL"] = ("Wheel-Version: 1.0\nGenerator: crawlcheck build_wheel.py\nRoot-Is-Purelib: true\nTag: %s\n" % tag).encode()
rec = []
for p, b in files.items():
    rec.append("%s,sha256=%s,%d" % (p, base64.urlsafe_b64encode(hashlib.sha256(b).digest()).decode().rstrip("="), len(b)))
rec.append(info + "/RECORD,,")
files[info + "/RECORD"] = ("\n".join(rec) + "\n").encode()
os.makedirs("dist", exist_ok=True)
out = "dist/%s-%s-%s.whl" % (name, V, tag)
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for p in files:
        zi = zipfile.ZipInfo(p, date_time=(2026, 10, 6, 0, 0, 0))
        zi.external_attr = 0o644 << 16
        zi.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(zi, files[p])
print(out, os.path.getsize(out), hashlib.sha256(open(out, "rb").read()).hexdigest())
