import argparse
import csv
import importlib.util
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_python_agent(agent_path: Path):
    spec = importlib.util.spec_from_file_location("python_agent_under_test", agent_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_manifest(path: Path):
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_csv(path: Path, rows):
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def severity_rank(verdict: str) -> int:
    return {"ALLOW": 0, "UNKNOWN": 0, "ALERT": 1, "TERMINATE": 2}.get((verdict or "").upper(), 0)


def size_bucket(size: int) -> str:
    if size < 1024:
        return "lt_1kb"
    if size < 10 * 1024:
        return "1kb_10kb"
    if size < 50 * 1024:
        return "10kb_50kb"
    if size < 200 * 1024:
        return "50kb_200kb"
    return "gte_200kb"


def split_reasons(value: str):
    return [item.strip() for item in (value or "").split(";") if item.strip()]


def main():
    parser = argparse.ArgumentParser(description="Evaluate The Stack PowerShell pilot with PythonAgent detection logic.")
    parser.add_argument("--files-manifest", required=True)
    parser.add_argument("--agent-path", default="PythonAgent/PythonAgent.py")
    parser.add_argument("--output-dir", default="datasets/the_stack/powershell_pilot/reports")
    parser.add_argument("--max-files", type=int, default=0, help="0 means evaluate all files.")
    parser.add_argument("--max-bytes", type=int, default=1024 * 1024)
    parser.add_argument("--extensions", default=".ps1,.psm1,.psd1", help="Comma-separated extension allowlist.")
    parser.add_argument("--enable-ml", action="store_true", help="Load PythonAgent ML model before evaluation.")
    args = parser.parse_args()

    files_manifest = Path(args.files_manifest).resolve()
    agent_path = Path(args.agent_path).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    agent = load_python_agent(agent_path)
    if args.enable_ml:
        agent.load_ml_model()

    rows = read_manifest(files_manifest)
    allowed_extensions = {item.strip().lower() for item in args.extensions.split(",") if item.strip()}
    if allowed_extensions:
        rows = [row for row in rows if row.get("file_extension", "").lower() in allowed_extensions]

    if args.max_files and args.max_files > 0:
        rows = rows[: args.max_files]

    results = []
    verdict_counts = Counter()
    rule_counts = Counter()
    ml_counts = Counter()
    risk_counts = Counter()
    extension_counts = defaultdict(lambda: Counter())
    size_counts = defaultdict(lambda: Counter())
    reason_counts = Counter()
    skipped = []

    for row in rows:
        path = Path(row.get("collected_path", ""))
        if not path.exists():
            skipped.append({"sample_id": row.get("sample_id", ""), "reason": "missing_file", "path": str(path)})
            continue

        size = path.stat().st_size
        if size > args.max_bytes:
            skipped.append({"sample_id": row.get("sample_id", ""), "reason": "file_too_large", "path": str(path), "size": size})
            continue

        text = path.read_text(encoding="utf-8", errors="ignore")
        event = {
            "source": "the_stack_static_eval",
            "pid": 0,
            "ppid": 0,
            "process": "static_script",
            "path": str(path),
            "script": text,
            "local_verdict": "ALLOW",
        }
        result = agent.build_detection_result(event)
        analysis = result.get("data_analysis", {})
        final_verdict = result.get("final_verdict", "ALLOW")
        rule_verdict = result.get("rule_verdict", "ALLOW")
        ml_verdict = result.get("ml_verdict", "UNKNOWN")
        risk_level = analysis.get("risk_level", "LOW")
        reasons = analysis.get("reasons", [])
        ext = row.get("file_extension", "").lower()
        bucket = size_bucket(size)

        verdict_counts[final_verdict] += 1
        rule_counts[rule_verdict] += 1
        ml_counts[ml_verdict] += 1
        risk_counts[risk_level] += 1
        extension_counts[ext][final_verdict] += 1
        size_counts[bucket][final_verdict] += 1
        for reason in reasons:
            reason_counts[reason] += 1

        results.append(
            {
                "sample_id": row.get("sample_id", ""),
                "source_dataset": row.get("source_dataset", ""),
                "dataset_version": row.get("dataset_version", ""),
                "label": row.get("label", ""),
                "category": row.get("category", ""),
                "repo_name": row.get("repo_name", ""),
                "repo_path": row.get("repo_path", ""),
                "license": row.get("license", ""),
                "file_extension": ext,
                "file_size_bytes": size,
                "size_bucket": bucket,
                "raw_sha256": row.get("raw_sha256", ""),
                "normalized_sha256": row.get("normalized_sha256", ""),
                "collected_path": str(path),
                "final_verdict": final_verdict,
                "rule_verdict": rule_verdict,
                "ml_enabled": result.get("ml_enabled", False),
                "ml_verdict": ml_verdict,
                "ml_confidence": result.get("ml_confidence", 0.0),
                "risk_level": risk_level,
                "risk_score": analysis.get("risk_score", 0.0),
                "raw_risk_score": analysis.get("raw_risk_score", 0.0),
                "benign_score": analysis.get("benign_score", 0.0),
                "reasons": "; ".join(reasons),
            }
        )

    suspicious_results = [
        row for row in results if severity_rank(row["final_verdict"]) >= severity_rank("ALERT")
    ]
    suspicious_results.sort(key=lambda item: (severity_rank(item["final_verdict"]), float(item.get("risk_score") or 0)), reverse=True)

    extension_summary = []
    for ext, counts in sorted(extension_counts.items()):
        total = sum(counts.values())
        extension_summary.append({
            "file_extension": ext,
            "evaluated_files": total,
            "allow": counts.get("ALLOW", 0),
            "alert": counts.get("ALERT", 0),
            "terminate": counts.get("TERMINATE", 0),
        })

    size_summary = []
    for bucket, counts in sorted(size_counts.items()):
        total = sum(counts.values())
        size_summary.append({
            "size_bucket": bucket,
            "evaluated_files": total,
            "allow": counts.get("ALLOW", 0),
            "alert": counts.get("ALERT", 0),
            "terminate": counts.get("TERMINATE", 0),
        })

    reason_summary = [
        {"reason": reason, "count": count}
        for reason, count in reason_counts.most_common()
    ]

    summary = {
        "files_manifest": str(files_manifest),
        "agent_path": str(agent_path),
        "ml_requested": bool(args.enable_ml),
        "ml_enabled": bool(getattr(agent, "ml_enabled", False)),
        "feature_columns_count": len(getattr(agent, "feature_columns", []) or []),
        "evaluated_files": len(results),
        "skipped_files": len(skipped),
        "final_verdict_counts": dict(verdict_counts),
        "rule_verdict_counts": dict(rule_counts),
        "ml_verdict_counts": dict(ml_counts),
        "risk_level_counts": dict(risk_counts),
        "alert_or_terminate_count": len(suspicious_results),
        "terminate_count": verdict_counts.get("TERMINATE", 0),
        "alert_count": verdict_counts.get("ALERT", 0),
        "note": "The Stack public code is not guaranteed benign; ALERT should be treated as review candidate, not automatic FP.",
    }

    (output_dir / "evaluation_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    (output_dir / "skipped_files.json").write_text(json.dumps(skipped, indent=2, ensure_ascii=False), encoding="utf-8")
    write_csv(output_dir / "evaluation_results.csv", results)
    write_csv(output_dir / "alert_or_terminate_results.csv", suspicious_results)
    write_csv(output_dir / "summary_by_extension.csv", extension_summary)
    write_csv(output_dir / "summary_by_size_bucket.csv", size_summary)
    write_csv(output_dir / "top_alert_reasons.csv", reason_summary)

    print("[THE-STACK EVAL] Completed.")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
