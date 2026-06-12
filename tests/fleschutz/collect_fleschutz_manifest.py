import argparse
import csv
import hashlib
import re
from pathlib import Path


STATE_CHANGING_KEYWORDS = [
    "add-",
    "change-",
    "clear-",
    "close-",
    "delete-",
    "disable-",
    "enable-",
    "hibernate",
    "install-",
    "kill-",
    "new-",
    "open-",
    "poweroff",
    "reboot",
    "remove-",
    "restart-",
    "save-",
    "set-",
    "shutdown",
    "start-",
    "stop-",
    "turn-",
    "uninstall-",
    "upgrade-",
]

ADMIN_KEYWORDS = [
    "firewall",
    "defender",
    "crashdump",
    "crash-dump",
    "service",
    "task",
    "updates",
    "ssh-server",
    "wsl",
    "windows-system-files",
]

NETWORK_KEYWORDS = [
    "dns",
    "download",
    "github",
    "internet",
    "ip-",
    "ping",
    "speed-test",
    "ssh",
    "url",
    "website",
    "wifi",
]

DISCOVERY_KEYWORDS = [
    "check-",
    "find-",
    "get-",
    "list-",
    "query-",
    "test-",
]

DEV_KEYWORDS = [
    "build",
    "git",
    "jenkins",
    "repo",
]

MEDIA_KEYWORDS = [
    "audio",
    "beep",
    "camera",
    "image",
    "music",
    "photo",
    "play-",
    "speak-",
    "video",
    "voice",
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_text(text: str) -> str:
    text = (text or "").replace("\x00", "").lower()
    text = re.sub(r"\s+", "", text)
    return text


def classify_script(name: str) -> str:
    lower = name.lower()

    if any(keyword in lower for keyword in ADMIN_KEYWORDS):
        return "admin_state_changing"

    if any(lower.startswith(keyword) for keyword in DISCOVERY_KEYWORDS):
        return "discovery_readonly"

    if any(keyword in lower for keyword in NETWORK_KEYWORDS):
        return "network_web_utility"

    if any(keyword in lower for keyword in DEV_KEYWORDS):
        return "dev_build_utility"

    if any(keyword in lower for keyword in MEDIA_KEYWORDS):
        return "media_user_utility"

    if any(lower.startswith(keyword) for keyword in STATE_CHANGING_KEYWORDS):
        return "user_state_changing"

    return "utility_misc"


def runtime_safety(category: str, name: str) -> str:
    lower = name.lower()
    if category in {"admin_state_changing", "user_state_changing"}:
        return "vm_checkpoint_required"
    if any(keyword in lower for keyword in ["install-", "reboot", "poweroff", "shutdown", "defender", "firewall"]):
        return "vm_checkpoint_required"
    return "static_or_manual_review"


def first_comment_summary(path: Path) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()[:30]:
            stripped = line.strip()
            if stripped.startswith("#"):
                text = stripped.lstrip("#").strip()
                if text and not text.startswith("requires"):
                    return text[:240]
    except Exception:
        return ""
    return ""


def main():
    parser = argparse.ArgumentParser(description="Create a manifest for fleschutz/PowerShell scripts.")
    parser.add_argument("--repo-root", default="datasets/fleschutz/PowerShell")
    parser.add_argument("--output", default="datasets/fleschutz/powershell_scripts/metadata/files_manifest.csv")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()
    scripts_dir = repo_root / "scripts"
    output_path = Path(args.output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for index, path in enumerate(sorted(scripts_dir.glob("*.ps1")), start=1):
        text = path.read_text(encoding="utf-8", errors="ignore")
        category = classify_script(path.name)
        rows.append(
            {
                "sample_id": f"fleschutz_{index:06d}",
                "source_dataset": "fleschutz_powershell",
                "label": "benign_public_script_unverified",
                "repo_name": "fleschutz/PowerShell",
                "license": "CC0-1.0",
                "file_name": path.name,
                "file_extension": path.suffix.lower(),
                "category": category,
                "runtime_safety": runtime_safety(category, path.name),
                "original_relative_path": str(path.relative_to(repo_root)),
                "collected_path": str(path),
                "file_size_bytes": path.stat().st_size,
                "raw_sha256": sha256_file(path),
                "normalized_sha256": hashlib.sha256(normalize_text(text).encode("utf-8", errors="ignore")).hexdigest(),
                "summary": first_comment_summary(path),
            }
        )

    fieldnames = list(rows[0].keys()) if rows else []
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[FLESCHUTZ] Manifest: {output_path}")
    print(f"[FLESCHUTZ] Scripts: {len(rows)}")


if __name__ == "__main__":
    main()
