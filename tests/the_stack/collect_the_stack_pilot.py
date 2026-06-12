import argparse
import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path


POWERSHELL_EXTENSIONS = {".ps1", ".psm1", ".psd1"}


def fail_dependency():
    message = {
        "status": "missing_dependency",
        "message": (
            "The Stack collector requires Hugging Face datasets dependencies. "
            "Install with: python -m pip install datasets huggingface-hub pyarrow"
        ),
    }
    print(json.dumps(message, indent=2))
    return 2


try:
    from datasets import load_dataset
except Exception:
    load_dataset = None


def sha256_text(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="ignore")).hexdigest()


def normalized_sha256(text: str) -> str:
    normalized = re.sub(r"\s+", "", (text or "").replace("\x00", "")).lower()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()


def safe_name(value: str, fallback: str = "unknown") -> str:
    value = (value or "").strip()
    value = re.sub(r'[\\/:*?"<>|]', "_", value)
    value = re.sub(r"\s+", "_", value)
    return value[:120] if value else fallback


def read_hashes_from_manifest(path: Path) -> tuple[set[str], set[str], int]:
    raw_hashes = set()
    normalized_hashes = set()
    if not path.exists():
        return raw_hashes, normalized_hashes, 0

    count = 0
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            count += 1
            raw = (row.get("raw_sha256") or "").strip().lower()
            norm = (row.get("normalized_sha256") or "").strip().lower()
            if raw:
                raw_hashes.add(raw)
            if norm:
                normalized_hashes.add(norm)
    return raw_hashes, normalized_hashes, count


def write_csv(path: Path, rows: list[dict]):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def extension_from_row(row: dict) -> str:
    ext = str(row.get("ext") or "").lower().strip()
    if ext and not ext.startswith("."):
        ext = "." + ext
    if ext in POWERSHELL_EXTENSIONS:
        return ext

    path = str(row.get("max_stars_repo_path") or row.get("path") or "").lower()
    for candidate in POWERSHELL_EXTENSIONS:
        if path.endswith(candidate):
            return candidate
    return ""


def repo_name_from_row(row: dict) -> str:
    for key in [
        "max_stars_repo_name",
        "max_forks_repo_name",
        "max_issues_repo_name",
        "repo_name",
    ]:
        value = row.get(key)
        if value:
            return str(value)
    return "unknown_repo"


def repo_path_from_row(row: dict) -> str:
    for key in [
        "max_stars_repo_path",
        "max_forks_repo_path",
        "max_issues_repo_path",
        "path",
    ]:
        value = row.get(key)
        if value:
            return str(value)
    return ""


def license_from_row(row: dict) -> str:
    for key in [
        "max_stars_repo_licenses",
        "max_forks_repo_licenses",
        "max_issues_repo_licenses",
        "licenses",
        "detected_licenses",
        "gha_license_id",
    ]:
        value = row.get(key)
        if value:
            if isinstance(value, list):
                return ";".join(str(item) for item in value)
            return str(value)
    return ""


def load_stack_stream(dataset_name: str, data_dir: str, split: str, token: str | None):
    kwargs = {
        "split": split,
        "streaming": True,
    }
    if data_dir:
        kwargs["data_dir"] = data_dir
    if token:
        kwargs["token"] = token
    return load_dataset(dataset_name, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect a small PowerShell pilot dataset from BigCode The Stack.")
    parser.add_argument("--dataset-name", default="bigcode/the-stack")
    parser.add_argument("--data-dir", default="data/powershell")
    parser.add_argument("--split", default="train")
    parser.add_argument("--output-root", default="datasets/the_stack/powershell_pilot")
    parser.add_argument("--target-total", type=int, default=150)
    parser.add_argument("--target-ps1", type=int, default=90)
    parser.add_argument("--target-psm1", type=int, default=40)
    parser.add_argument("--target-psd1", type=int, default=20)
    parser.add_argument("--max-file-size-kb", type=int, default=200)
    parser.add_argument("--min-file-size-bytes", type=int, default=200)
    parser.add_argument("--max-files-per-repo", type=int, default=5)
    parser.add_argument("--max-stream-items", type=int, default=50000)
    parser.add_argument("--hf-token-env", default="HF_TOKEN")
    parser.add_argument(
        "--dedup-manifest",
        action="append",
        default=[
            "datasets/powershell_gallery/behavior_groups_80/metadata/files_manifest.csv",
            "datasets/chocolatey/behavior_groups_80_casefixed/metadata/files_manifest.csv",
        ],
    )
    args = parser.parse_args()

    if load_dataset is None:
        return fail_dependency()

    output_root = Path(args.output_root).resolve()
    scripts_root = output_root / "extracted_scripts"
    metadata_root = output_root / "metadata"
    scripts_root.mkdir(parents=True, exist_ok=True)
    metadata_root.mkdir(parents=True, exist_ok=True)

    existing_raw = set()
    existing_norm = set()
    dedup_sources = []
    for manifest in args.dedup_manifest or []:
        manifest_path = Path(manifest)
        raw, norm, count = read_hashes_from_manifest(manifest_path)
        existing_raw.update(raw)
        existing_norm.update(norm)
        dedup_sources.append({
            "manifest": str(manifest_path),
            "rows": count,
            "raw_hashes": len(raw),
            "normalized_hashes": len(norm),
            "exists": manifest_path.exists(),
        })

    target_by_ext = {
        ".ps1": args.target_ps1,
        ".psm1": args.target_psm1,
        ".psd1": args.target_psd1,
    }
    selected_by_ext = Counter()
    per_repo_counts = Counter()
    skip_counts = Counter()
    duplicate_rows = []
    manifest_rows = []
    seen_raw = set()
    seen_norm = set()
    max_bytes = args.max_file_size_kb * 1024
    token = os.environ.get(args.hf_token_env) or None

    try:
        stream = load_stack_stream(args.dataset_name, args.data_dir, args.split, token)
    except Exception as exc:
        error = {
            "status": "dataset_access_error",
            "dataset_name": args.dataset_name,
            "data_dir": args.data_dir,
            "split": args.split,
            "token_env": args.hf_token_env,
            "has_token": bool(token),
            "error_type": type(exc).__name__,
            "error": str(exc),
            "hint": (
                "Check network access, install dependencies, log in to Hugging Face, "
                "accept The Stack terms, and set HF_TOKEN if required."
            ),
        }
        (metadata_root / "collection_error.json").write_text(json.dumps(error, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(error, indent=2, ensure_ascii=False))
        return 3

    processed = 0
    for row in stream:
        processed += 1
        if args.max_stream_items and processed > args.max_stream_items:
            skip_counts["max_stream_items_reached"] += 1
            break

        ext = extension_from_row(row)
        if ext not in POWERSHELL_EXTENSIONS:
            skip_counts["extension_not_selected"] += 1
            continue

        if selected_by_ext[ext] >= target_by_ext.get(ext, 0):
            skip_counts[f"{ext}_target_reached"] += 1
            if sum(selected_by_ext.values()) >= args.target_total or all(selected_by_ext[e] >= target_by_ext[e] for e in target_by_ext):
                break
            continue

        content = row.get("content")
        if not isinstance(content, str) or not content.strip():
            skip_counts["missing_content"] += 1
            continue

        size_bytes = len(content.encode("utf-8", errors="ignore"))
        if size_bytes < args.min_file_size_bytes:
            skip_counts["file_too_small"] += 1
            continue
        if size_bytes > max_bytes:
            skip_counts["file_too_large"] += 1
            continue

        raw_hash = sha256_text(content)
        norm_hash = normalized_sha256(content)
        duplicate_reason = ""
        if raw_hash in existing_raw or norm_hash in existing_norm:
            duplicate_reason = "duplicate_existing_dataset"
        elif raw_hash in seen_raw or norm_hash in seen_norm:
            duplicate_reason = "duplicate_current_collection"

        repo_name = repo_name_from_row(row)
        repo_path = repo_path_from_row(row)
        repo_key = repo_name.lower()

        if duplicate_reason:
            duplicate_rows.append({
                "source_dataset": args.dataset_name,
                "repo_name": repo_name,
                "repo_path": repo_path,
                "file_extension": ext,
                "raw_sha256": raw_hash,
                "normalized_sha256": norm_hash,
                "duplicate_reason": duplicate_reason,
            })
            skip_counts[duplicate_reason] += 1
            continue

        if args.max_files_per_repo and per_repo_counts[repo_key] >= args.max_files_per_repo:
            skip_counts["max_files_per_repo"] += 1
            continue

        selected_by_ext[ext] += 1
        per_repo_counts[repo_key] += 1
        seen_raw.add(raw_hash)
        seen_norm.add(norm_hash)

        sample_index = sum(selected_by_ext.values())
        sample_id = f"stack_pilot_{sample_index:06d}"
        safe_repo = safe_name(repo_name, "repo")
        original_name = safe_name(Path(repo_path).name, f"sample{ext}")
        if not original_name.lower().endswith(ext):
            original_name = f"{original_name}{ext}"
        relative_dir = scripts_root / ext.strip(".") / safe_repo
        relative_dir.mkdir(parents=True, exist_ok=True)
        collected_path = relative_dir / f"{sample_id}_{original_name}"
        collected_path.write_text(content, encoding="utf-8", errors="ignore")

        manifest_rows.append({
            "sample_id": sample_id,
            "source_dataset": args.dataset_name,
            "dataset_version": "the-stack-v1",
            "label": "unknown_public_code",
            "category": "the_stack_generalization",
            "repo_name": repo_name,
            "repo_path": repo_path,
            "license": license_from_row(row),
            "file_extension": ext,
            "file_size_bytes": size_bytes,
            "raw_sha256": raw_hash,
            "normalized_sha256": norm_hash,
            "collected_path": str(collected_path),
            "original_relative_path": repo_path,
            "max_stars_count": row.get("max_stars_count", ""),
            "max_forks_count": row.get("max_forks_count", ""),
            "max_issues_count": row.get("max_issues_count", ""),
        })

        if sum(selected_by_ext.values()) >= args.target_total or all(selected_by_ext[e] >= target_by_ext[e] for e in target_by_ext):
            break

    summary = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "status": "completed",
        "source_dataset": args.dataset_name,
        "data_dir": args.data_dir,
        "split": args.split,
        "output_root": str(output_root),
        "processed_stream_items": processed,
        "selected_total": len(manifest_rows),
        "selected_by_extension": dict(selected_by_ext),
        "target_total": args.target_total,
        "target_by_extension": target_by_ext,
        "max_file_size_kb": args.max_file_size_kb,
        "min_file_size_bytes": args.min_file_size_bytes,
        "max_files_per_repo": args.max_files_per_repo,
        "skip_counts": dict(skip_counts),
        "dedup_sources": dedup_sources,
        "notes": [
            "Scripts are collected for static evaluation only.",
            "The Stack public code should not be treated as guaranteed benign.",
            "The holdout must not be used for tuning unless a separate tuning split is created.",
        ],
    }

    write_csv(metadata_root / "files_manifest.csv", manifest_rows)
    write_csv(metadata_root / "duplicate_manifest.csv", duplicate_rows)
    (metadata_root / "collection_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))
    if not manifest_rows:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
