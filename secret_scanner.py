import os
import re
import sys
import json
import argparse
import tempfile
import shutil
import subprocess
import requests
import base64
from urllib.parse import urlparse
from typing import Dict, List, Tuple

# --------------------
# Configuration
# --------------------
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Access Key (possible)": re.compile(
        r"\baws(.{0,20})?(?:secret|secret_access)_?key(.{0,20})?[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?\b",
        re.IGNORECASE
    ),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Slack Token": re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    "Private Key Header": re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH)? ?PRIVATE KEY-----"),
    "SSH OPENSSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "JWT (likely)": re.compile(r"\beyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.([A-Za-z0-9\-_.+/=]*)\b"),
    "Stripe Live Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
}

IGNORE_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "env", ".env", ".idea"}
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".exe", ".dll", ".so", ".bin", ".pdf", ".zip", ".tar", ".gz", ".mp4"}

# file extensions we consider text-like for API direct fetch (also controlled by ext check)
TEXT_EXTS = {".py", ".txt", ".md", ".json", ".yaml", ".yml", ".env", ".ini", ".cfg", ".js", ".ts", ".html", ".css", ".rb", ".go"}

# --------------------
# Helpers
# --------------------
def is_text_like(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in TEXT_EXTS or ext == ""

def scan_text_content(path_label: str, text: str) -> List[Dict]:
    findings = []
    if not text:
        return findings
    for name, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            snippet = m.group(0)
            # approximate line number
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append({
                "type": name,
                "match": snippet,
                "line": line_no,
                "path": path_label
            })
    # simple high-entropy check (optional): strings of base64-like chars >= 30
    for m in re.finditer(r"[A-Za-z0-9\-_+/=]{30,}", text):
        s = m.group(0)
        # compute entropy bits per char (simple heuristic)
        # quick filter: if no lower/upper/digits mix then skip
        if len(set(s)) > 10:
            findings.append({
                "type": "High Entropy String",
                "match": s[:120],
                "line": None,
                "path": path_label
            })
    return findings


def scan_file_local(fullpath: str) -> List[Dict]:
    try:
        with open(fullpath, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
    except Exception:
        return []
    return scan_text_content(fullpath, content)

def scan_directory_local(root: str) -> Dict[str, List[Dict]]:
    report = {}
    for dirpath, dirnames, filenames in os.walk(root):
        # modify dirnames in-place to skip ignored dirs
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]
        for fname in filenames:
            full = os.path.join(dirpath, fname)
            _, ext = os.path.splitext(full)
            if ext.lower() in IGNORE_EXTS:
                continue
            findings = scan_file_local(full)
            if findings:
                report[full] = findings
    return report


def clone_repo(repo_url: str) -> str:
    tmp_dir = tempfile.mkdtemp(prefix="repo_scan_")
    try:
        subprocess.run(["git", "clone", "--depth", "1", repo_url, tmp_dir], check=True, stdout=subprocess.DEVNULL)
        return tmp_dir
    except subprocess.CalledProcessError:
        shutil.rmtree(tmp_dir)
        raise

# --------------------
# GitHub API direct fetch (no clone)
# --------------------
def parse_github_url(url: str) -> Tuple[str, str]:
    # expects https://github.com/owner/repo or with .git suffix
    parsed = urlparse(url)
    if parsed.netloc not in ("github.com", "www.github.com"):
        raise ValueError("Not a github.com URL")
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError("Malformed GitHub URL")
    owner, repo = parts[0], parts[1].removesuffix(".git")
    return owner, repo

def github_api_request(path: str, token: str = None):
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"
    url = f"https://api.github.com{path}"
    resp = requests.get(url, headers=headers, timeout=30)
    if resp.status_code == 403 and "X-RateLimit-Remaining" in resp.headers and resp.headers.get("X-RateLimit-Remaining") == "0":
        raise RuntimeError("GitHub API rate limit exceeded")
    resp.raise_for_status()
    return resp.json()

def scan_github_repo_direct(owner: str, repo: str, token: str = None) -> Dict[str, List[Dict]]:
    """
    Fetch the repo tree via GitHub API and scan text blobs in memory.
    Only pulls blobs for text-like files (by extension).
    """
    report = {}
    # 1) get default branch
    repo_info = github_api_request(f"/repos/{owner}/{repo}", token)
    default_branch = repo_info.get("default_branch", "master")

    # 2) get tree recursively
    tree = github_api_request(f"/repos/{owner}/{repo}/git/trees/{default_branch}?recursive=1", token)
    if "tree" not in tree:
        return report

    for entry in tree["tree"]:
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        # skip binary-like by extension
        if not is_text_like(path):
            continue
        sha = entry.get("sha")
        # fetch blob
        blob = github_api_request(f"/repos/{owner}/{repo}/git/blobs/{sha}", token)
        content_b64 = blob.get("content", "")
        if not content_b64:
            continue
        try:
            raw = base64.b64decode(content_b64, validate=True)
            # small safety cap: skip very large files
            if len(raw) > 2_000_000:  # 2MB
                continue
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
        findings = scan_text_content(f"github://{owner}/{repo}/{path}", text)
        if findings:
            report[path] = findings
    return report


def build_parser():
    p = argparse.ArgumentParser(description="Secret scanner (local or GitHub API direct scan)")
    p.add_argument("target", help="Local path or GitHub URL to scan")
    p.add_argument("--direct", action="store_true", help="For GitHub URLs: fetch via GitHub API (no git clone)")
    p.add_argument("--report", "-r", help="Write JSON report to this file")
    return p

def main():
    args = build_parser().parse_args()
    target = args.target
    results = {}

    # detect GitHub URL
    is_github = target.startswith("https://github.com/") or target.startswith("http://github.com/")

    if is_github and args.direct:
        token = os.getenv("GITHUB_TOKEN")
        try:
            owner, repo = parse_github_url(target)
        except Exception as e:
            print("Invalid GitHub URL:", e)
            sys.exit(2)
        try:
            print(f"Scanning GitHub repo via API: {owner}/{repo} (no clone).")
            results = scan_github_repo_direct(owner, repo, token)
        except RuntimeError as e:
            print("Error:", e)
            sys.exit(2)
        except requests.HTTPError as e:
            print("HTTP error from GitHub API:", e)
            sys.exit(2)
    elif is_github and not args.direct:
        # fallback to clone
        try:
            tmp = clone_repo(target)
            print(f"Cloned to {tmp} — scanning...")
            results = scan_directory_local(tmp)
            shutil.rmtree(tmp)
        except Exception as e:
            print("Git clone failed:", e)
            sys.exit(2)
    else:
        # local path
        if not os.path.exists(target):
            print("Local path does not exist:", target)
            sys.exit(2)
        results = scan_directory_local(target)

    # print summary
    total = sum(len(v) for v in results.values())
    if total == 0:
        print("No findings.")
    else:
        print(f"Findings: {total} potential secrets in {len(results)} files\n")
        for path, findings in results.items():
            print(f"== {path} ==")
            for f in findings:
                t = f.get("type")
                m = f.get("match")
                ln = f.get("line")
                print(f" - {t} (line: {ln}) -> {m if len(str(m))<200 else str(m)[:200]+'...'}")
            print()

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as out:
                json.dump(results, out, indent=2, ensure_ascii=False)
            print("Report written to", args.report)
        except Exception as e:
            print("Failed to write report:", e)

if __name__ == "__main__":
    main()
