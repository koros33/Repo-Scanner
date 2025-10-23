### Overview

`secret_scanner.py` is a lightweight Python-based security auditing tool that scans **local directories** or **public GitHub repositories** for potential secrets such as API keys, private keys, or tokens accidentally committed to source code.

It supports two modes:

* **Local Scan:** Scans any local project folder.
* **GitHub Scan:** Either clones the repo or fetches files directly using the **GitHub API** (no clone).


### 🧠 Features

* Detects common secrets:

  * AWS Access Keys
  * Google API Keys
  * Slack Tokens
  * JWTs
  * Stripe Live Keys
  * Private Key Blocks
* High-entropy string detection (flags suspicious random strings)
* Works locally or remotely via GitHub API
* Optional JSON report generation


### 🛠️ Requirements

* **Python 3.7+**
* **Git** (only if using the clone mode)
* **Dependencies:**

  ```bash
  pip install requests
  ```


### 🚀 Usage

#### 1. Scan a local project folder

```bash
python secret_scanner.py /path/to/repo
```

#### 2. Scan a GitHub repository by cloning

```bash
python secret_scanner.py https://github.com/owner/repo
```

#### 3. Scan a GitHub repository directly via API (no clone)

```bash
python secret_scanner.py https://github.com/owner/repo --direct
```

*(Optional)* You can use a GitHub token to avoid API rate limits:

```bash
export GITHUB_TOKEN=your_personal_access_token
python secret_scanner.py https://github.com/owner/repo --direct
```

#### 4. Save results to a JSON report

```bash
python secret_scanner.py /path/to/repo --report results.json
```


### 📄 Output Example

```
Scanning GitHub repo via API: user/project (no clone).
Findings: 3 potential secrets in 2 files

== github://user/project/config.py ==
 - AWS Access Key ID (line: 23) -> AKIAIOSFODNN7EXAMPLE
 - AWS Secret Access Key (possible) (line: 24) -> wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

== github://user/project/.env ==
 - Stripe Live Key (line: 5) -> sk_live_4eC39HqLyjWDarjtT1zdp7dc
```

## 🧭 Ethics & Responsible Use

**This tool is designed for ethical and legal use only.**
You may **only scan repositories or directories you own, manage, or have explicit permission to test.**

### ✅ Responsible Usage

* Use it on your own projects to prevent credential leaks.
* Use it in corporate security audits **with written authorization**.
* Use it as a learning tool for secure coding and DevSecOps practices.

### ❌ Prohibited Usage

* Scanning other users’ GitHub repositories without permission.
* Using the tool to harvest or expose sensitive data.
* Circumventing API rate limits or security controls.

Violating GitHub’s or any platform’s **Terms of Service** or **Computer Misuse laws** can lead to legal consequences.

