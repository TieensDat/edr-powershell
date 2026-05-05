import os
import json
import re
from typing import Any, Dict, List, Optional
from datetime import datetime, time as dt_time
from dotenv import load_dotenv

load_dotenv()

DEFAULT_EVENT_LOG_PATH = os.environ.get(
    "EDR_EVENTS_LOG_PATH",
    r"D:\KLTN\EDR_Project\PythonAgent\logs\edr_events.jsonl"
)

DEFAULT_CPP_LOG_PATH = os.environ.get(
    "EDR_CPP_LOG_PATH",
    r"D:\KLTN\EDR_Project\PythonAgent\logs\edr_cpp_agent.log"
)


# =====================================================
# BASIC LOG READING
# =====================================================
def is_report_noise_event(event: Dict[str, Any]) -> bool:
    script = (event.get("script") or "").lower().replace(" ", "")
    process = (event.get("process") or "").lower()

    if "127.0.0.1:9001/health" in script or "localhost:9001/health" in script:
        return True

    if script in {"prompt", "$global:?", "global:?"}:
        return True

    if "pcasvc.dll" in script:
        return True

    if "appxdeploymentextensions.onecore.dll" in script:
        return True

    if process == "rundll32.exe" and (
        "appxdeploymentextensions.onecore.dll" in script
        or "pcasvc.dll" in script
    ):
        return True

    return False


def read_events(log_path: str = DEFAULT_EVENT_LOG_PATH) -> List[Dict[str, Any]]:
    events = []

    if not os.path.exists(log_path):
        print("[LOG] edr_events.jsonl not found:", log_path)
        return events

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
                if is_report_noise_event(event):
                    continue
                events.append(event)
            except Exception:
                continue

    print(f"[LOG] Loaded Python events: {len(events)} from {log_path}")
    return events


# =====================================================
# C++ LOG PARSER
# =====================================================
def read_cpp_log(log_path: str = DEFAULT_CPP_LOG_PATH) -> List[Dict[str, Any]]:
    if not os.path.exists(log_path):
        print("[LOG] C++ log not found:", log_path)
        return []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        text = f.read()

    return parse_cpp_log(text)


def parse_cpp_log(text: str) -> List[Dict[str, Any]]:
    records = []

    current = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        ts_match = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+(.*)", line)
        if not ts_match:
            continue

        timestamp = ts_match.group(1)
        body = ts_match.group(2)

        if "========================================" in body:
            if current:
                records.append(current)
            current = {
                "time": timestamp,
                "pid": None,
                "ppid": None,
                "process": None,
                "parent_process": None,
                "hash": None,
                "local_verdict": None,
                "script": "",
                "forward_ok": False,
                "python_verdict": None,
                "action": None,
                "error": None,
            }
            continue

        if current is None:
            # Global log lines, not event block.
            continue

        if body.startswith("[AMSI]"):
            m = re.search(
                r"PID=(\d+)\s+PPID=(\d+)\s+PROC=([^\s]+)\s+PARENT=([^\s]+)",
                body
            )
            if m:
                current["pid"] = int(m.group(1))
                current["ppid"] = int(m.group(2))
                current["process"] = m.group(3)
                current["parent_process"] = m.group(4)

        elif body.startswith("[HASH]"):
            current["hash"] = body.replace("[HASH]", "").strip()

        elif body.startswith("[LOCAL]"):
            m = re.search(r"verdict=([A-Z]+)", body)
            if m:
                current["local_verdict"] = m.group(1)

        elif body.startswith("[SCRIPT]"):
            current["script"] = body.replace("[SCRIPT]", "").strip()

        elif body.startswith("[FORWARD]"):
            current["forward_ok"] = True

        elif body.startswith("[PYTHON_AGENT]"):
            m = re.search(r"verdict=([A-Z]+)", body)
            if m:
                current["python_verdict"] = m.group(1)

        elif body.startswith("[ACTION]"):
            current["action"] = body

        elif body.startswith("[ERROR]") or body.startswith("[WARN]"):
            current["error"] = body

    if current:
        records.append(current)

    print(f"[LOG] Loaded C++ records: {len(records)}")
    return records


# =====================================================
# QUERY PARSING
# =====================================================
def extract_pid(question: str) -> Optional[int]:
    q = question or ""

    match = re.search(
        r"\b(?:pid|process\s*id)\s*[:=]?\s*(\d{2,10})\b",
        q,
        flags=re.IGNORECASE
    )

    if match:
        return int(match.group(1))

    return None


def extract_process_name(question: str) -> Optional[str]:
    q = (question or "").lower()

    known_processes = [
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "schtasks.exe",
    ]

    for proc in known_processes:
        if proc in q:
            return proc

    return None


def extract_source_filter(question: str) -> Optional[str]:
    q = (question or "").lower()

    if "amsi" in q:
        return "amsi_cpp_bridge"

    if "file_sensor" in q or "file sensor" in q:
        return "file_sensor"

    if "process_sensor" in q or "process sensor" in q:
        return "process_sensor"

    if "eventlog" in q or "event log" in q or "4104" in q:
        return "eventlog_4104_sensor"

    return None


def extract_verdict_filter(question: str) -> Optional[str]:
    q = (question or "").lower()

    if "terminate" in q or "terminated" in q or "bị chặn" in q or "bị kill" in q:
        return "TERMINATE"

    if "alert" in q or "cảnh báo" in q:
        return "ALERT"

    if "allow" in q or "benign" in q or "lành tính" in q:
        return "ALLOW"

    return None


def extract_keyword_filter(question: str) -> Optional[str]:
    q = (question or "").lower()

    keywords = [
        "encodedcommand",
        "invoke-expression",
        "iex",
        "set-mppreference",
        "downloadstring",
        "invoke-webrequest",
        "amsiutils",
        "amsiinitfailed",
        "mimikatz",
        "test_edr.ps1",
        "defender_test.ps1",
    ]

    for keyword in keywords:
        if keyword in q:
            return keyword

    return None


def extract_time_filters(question: str) -> Dict[str, Optional[str]]:
    q = (question or "").lower()

    result = {
        "start": None,
        "end": None,
        "exact": None,
    }

    times = re.findall(
        r"\b(?:[01]?\d|2[0-3]):[0-5]\d(?::[0-5]\d)?\b",
        q
    )

    if len(times) >= 2:
        result["start"] = times[0]
        result["end"] = times[1]
        return result

    if len(times) >= 1 and ("sau" in q or "after" in q):
        result["start"] = times[0]
        return result

    if len(times) >= 1 and ("trước" in q or "before" in q):
        result["end"] = times[0]
        return result

    if len(times) >= 1 and ("lúc" in q or "at" in q):
        result["exact"] = times[0]
        return result

    return result


def infer_intent(question: str) -> str:
    q = (question or "").lower()

    if "báo cáo" in q or "report" in q or "viết báo cáo" in q:
        return "generate_report"

    if "chuỗi" in q or "attack chain" in q or "timeline" in q:
        return "build_timeline"

    if "terminate" in q or "terminated" in q or "bị chặn" in q or "bị kill" in q:
        return "explain_terminate"

    if "alert" in q or "cảnh báo" in q:
        return "explain_alert"

    if "liệt kê" in q or "list" in q or "event" in q:
        return "list_events"

    return "general_explain"


def generate_investigation_queries(question: str, intent: str) -> Dict[str, Any]:
    """
    Đây là node 'agentic' nhẹ:
    phân rã câu hỏi thành điều kiện điều tra và câu hỏi con.
    Không cần LLM ở bước này để tiết kiệm token.
    """
    filters = {
        "pid": extract_pid(question),
        "process": extract_process_name(question),
        "source": extract_source_filter(question),
        "verdict": extract_verdict_filter(question),
        "keyword": extract_keyword_filter(question),
        "time": extract_time_filters(question),
    }

    subquestions = []

    if filters["pid"]:
        subquestions.append(f"Các event nào liên quan PID {filters['pid']}?")
    if filters["process"]:
        subquestions.append(f"Các event nào liên quan process {filters['process']}?")
    if filters["source"]:
        subquestions.append(f"Sensor {filters['source']} phát hiện gì?")
    if filters["verdict"]:
        subquestions.append(f"Các event có verdict {filters['verdict']} là gì?")
    if filters["keyword"]:
        subquestions.append(f"Các event nào chứa keyword {filters['keyword']}?")
    if filters["time"].get("start") or filters["time"].get("end") or filters["time"].get("exact"):
        subquestions.append(f"Các event nào nằm trong khoảng thời gian {filters['time']}?")

    if intent == "generate_report":
        subquestions.append("Tạo báo cáo điều tra dựa trên các event đã lọc.")
    elif intent == "build_timeline":
        subquestions.append("Dựng timeline và attack chain.")
    elif intent in {"explain_alert", "explain_terminate"}:
        subquestions.append("Giải thích vì sao verdict được đưa ra.")
    else:
        subquestions.append("Tóm tắt các event liên quan.")

    return {
        "filters": filters,
        "subquestions": subquestions,
    }


# =====================================================
# FILTERING
# =====================================================
def parse_event_time(event: Dict[str, Any]) -> Optional[datetime]:
    value = event.get("received_at_human")
    if not value:
        return None

    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def parse_hms_to_time(value: str) -> Optional[dt_time]:
    if not value:
        return None

    parts = value.split(":")
    try:
        if len(parts) == 2:
            return dt_time(int(parts[0]), int(parts[1]), 0)
        if len(parts) == 3:
            return dt_time(int(parts[0]), int(parts[1]), int(parts[2]))
    except Exception:
        return None

    return None


def filter_by_time(events: List[Dict[str, Any]], time_filters: Dict[str, Optional[str]]) -> List[Dict[str, Any]]:
    start_s = time_filters.get("start")
    end_s = time_filters.get("end")
    exact_s = time_filters.get("exact")

    if not start_s and not end_s and not exact_s:
        return events

    start_t = parse_hms_to_time(start_s) if start_s else None
    end_t = parse_hms_to_time(end_s) if end_s else None
    exact_t = parse_hms_to_time(exact_s) if exact_s else None

    filtered = []

    for event in events:
        dt = parse_event_time(event)
        if not dt:
            continue

        event_t = dt.time()

        if exact_t:
            if event_t.hour == exact_t.hour and event_t.minute == exact_t.minute:
                filtered.append(event)
            continue

        if start_t and event_t < start_t:
            continue

        if end_t and event_t > end_t:
            continue

        filtered.append(event)

    return filtered


def event_matches_process(event: Dict[str, Any], process_name: str) -> bool:
    process_name = (process_name or "").lower()
    process = (event.get("process") or "").lower()
    script = (event.get("script") or "").lower()
    source = (event.get("source") or "").lower()

    if process == process_name:
        return True

    if process_name in script:
        return True

    # EventLog 4104 bản chất là PowerShell ScriptBlock Logging.
    if process_name in {"powershell.exe", "pwsh.exe"}:
        if process == "powershell_eventlog":
            return True
        if source == "eventlog_4104_sensor":
            return True

    return False


def filter_events(events: List[Dict[str, Any]], question: str, intent: str, investigation: Dict[str, Any] | None = None) -> List[Dict[str, Any]]:
    if investigation is None:
        investigation = generate_investigation_queries(question, intent)

    filters = investigation.get("filters", {})

    pid = filters.get("pid")
    process_name = filters.get("process")
    source_filter = filters.get("source")
    verdict_filter = filters.get("verdict")
    keyword_filter = filters.get("keyword")
    time_filters = filters.get("time") or {}

    selected = events

    if pid is not None:
        selected = [
            e for e in selected
            if int(e.get("pid") or 0) == pid
        ]

    if process_name:
        selected = [
            e for e in selected
            if event_matches_process(e, process_name)
        ]

    if source_filter:
        selected = [
            e for e in selected
            if e.get("source") == source_filter
        ]

    if verdict_filter:
        selected = [
            e for e in selected
            if (e.get("final_verdict") or "").upper() == verdict_filter
        ]

    if keyword_filter:
        selected = [
            e for e in selected
            if keyword_filter in (e.get("script") or "").lower()
            or keyword_filter in (e.get("path") or "").lower()
            or keyword_filter in json.dumps(e.get("data_analysis", {}).get("reasons", []), ensure_ascii=False).lower()
        ]

    selected = filter_by_time(selected, time_filters)

    has_specific_filter = any([
        pid is not None,
        process_name,
        source_filter,
        verdict_filter,
        keyword_filter,
        time_filters.get("start"),
        time_filters.get("end"),
        time_filters.get("exact"),
    ])

    print("[FILTER DEBUG]")
    print("filters:", filters)
    print("input events:", len(events))
    print("selected events:", len(selected))

    if has_specific_filter:
        return selected[-30:]

    if intent == "explain_terminate":
        return [
            e for e in events
            if (e.get("final_verdict") or "").upper() == "TERMINATE"
        ][-10:]

    if intent == "explain_alert":
        return [
            e for e in events
            if (e.get("final_verdict") or "").upper() == "ALERT"
        ][-10:]

    suspicious = [
        e for e in events
        if (e.get("final_verdict") or "").upper() in {"ALERT", "TERMINATE"}
    ]

    return suspicious[-10:]


# =====================================================
# CORRELATION
# =====================================================
def safe_script_prefix(script: str, limit: int = 80) -> str:
    return " ".join((script or "").lower().split())[:limit]


def parse_time_str(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def correlate_cpp_context(events: List[Dict[str, Any]], cpp_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    correlated = []

    for event in events:
        event_time = parse_event_time(event)
        event_hash = event.get("sha256")
        event_pid = event.get("pid")
        event_script_prefix = safe_script_prefix(event.get("script", ""))

        matches = []

        for record in cpp_records:
            record_time = parse_time_str(record.get("time"))
            record_hash = record.get("hash")
            record_pid = record.get("pid")
            record_script_prefix = safe_script_prefix(record.get("script", ""))

            score = 0

            if event_hash and record_hash and event_hash == record_hash:
                score += 5

            if event_pid and record_pid and int(event_pid) == int(record_pid):
                score += 2

            if event_script_prefix and record_script_prefix and (
                event_script_prefix in record_script_prefix
                or record_script_prefix in event_script_prefix
            ):
                score += 2

            if event_time and record_time:
                diff = abs((event_time - record_time).total_seconds())
                if diff <= 3:
                    score += 2
                elif diff <= 10:
                    score += 1

            if score >= 4:
                matches.append({
                    "score": score,
                    "cpp_time": record.get("time"),
                    "cpp_pid": record.get("pid"),
                    "cpp_process": record.get("process"),
                    "cpp_hash": record.get("hash"),
                    "cpp_local_verdict": record.get("local_verdict"),
                    "cpp_forward_ok": record.get("forward_ok"),
                    "cpp_python_verdict": record.get("python_verdict"),
                    "cpp_action": record.get("action"),
                    "cpp_error": record.get("error"),
                    "cpp_script": record.get("script", "")[:300],
                })

        event_copy = dict(event)
        event_copy["cpp_context"] = sorted(matches, key=lambda x: x["score"], reverse=True)[:2]
        correlated.append(event_copy)

    return correlated


# =====================================================
# CONTEXT BUILDING
# =====================================================
def compact_event(event: Dict[str, Any]) -> Dict[str, Any]:
    analysis = event.get("data_analysis", {}) or {}
    cpp_context = event.get("cpp_context", [])

    return {
        "time": event.get("received_at_human"),
        "source": event.get("source"),
        "pid": event.get("pid"),
        "process": event.get("process"),
        "path": event.get("path"),
        "sha256": event.get("sha256"),
        "local_verdict": event.get("local_verdict"),
        "rule_verdict": event.get("rule_verdict"),
        "ml_enabled": event.get("ml_enabled"),
        "ml_verdict": event.get("ml_verdict"),
        "ml_confidence": event.get("ml_confidence"),
        "final_verdict": event.get("final_verdict"),
        "risk_level": analysis.get("risk_level"),
        "risk_score": analysis.get("risk_score"),
        "raw_risk_score": analysis.get("raw_risk_score"),
        "benign_score": analysis.get("benign_score"),
        "reasons": analysis.get("reasons", []),
        "attack_phases": map_attack_phase(event),
        "script": (event.get("script") or "")[:350],
        "cpp_context": cpp_context,
    }


def map_attack_phase(event: Dict[str, Any]) -> List[str]:
    features = event.get("features", {}) or {}
    script = (event.get("script") or "").lower()
    source = event.get("source")

    phases = []

    if source in {"amsi_cpp_bridge", "process_sensor", "file_sensor", "eventlog_4104_sensor"}:
        phases.append("Execution")

    if features.get("encoded_cmd") or features.get("num_frombase64") or features.get("has_base64_payload"):
        phases.append("Obfuscation / Encoding")

    if features.get("iex_count") or features.get("has_IEX_alias") or "invoke-expression" in script or "iex" in script:
        phases.append("Dynamic Execution")

    if features.get("iwr_count") or features.get("num_webclient") or features.get("num_downloadfile"):
        phases.append("Download / Remote Payload")

    if features.get("amsi_bypass") or features.get("add_mp_preference") or features.get("clear_eventlog"):
        phases.append("Defense Evasion")

    if features.get("reg_add") or features.get("schtasks") or features.get("has_persistence"):
        phases.append("Persistence")

    if features.get("has_cred_dump") or "mimikatz" in script or "sekurlsa" in script or "logonpasswords" in script:
        phases.append("Credential Access")

    if (event.get("final_verdict") or "").upper() == "TERMINATE":
        phases.append("Response / Process Termination")

    if not phases:
        phases.append("Informational")

    return phases


def build_timeline(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ordered = sorted(events, key=lambda e: e.get("received_at", 0))
    return [compact_event(e) for e in ordered]


def summarize_verdict(events: List[Dict[str, Any]]) -> str:
    verdicts = [(e.get("final_verdict") or "ALLOW").upper() for e in events]

    if "TERMINATE" in verdicts:
        return "TERMINATE"

    if "ALERT" in verdicts:
        return "ALERT"

    return "ALLOW"


def build_context(
    events: List[Dict[str, Any]],
    investigation: Dict[str, Any] | None = None,
    limit: int = 10
) -> Dict[str, Any]:
    selected = events[-limit:]
    timeline = build_timeline(selected)

    phases = []
    sources = []
    verdicts = []
    processes = []
    pids = []

    for item in timeline:
        for phase in item.get("attack_phases", []):
            if phase not in phases:
                phases.append(phase)

        if item.get("source") not in sources:
            sources.append(item.get("source"))

        if item.get("final_verdict") not in verdicts:
            verdicts.append(item.get("final_verdict"))

        if item.get("process") not in processes:
            processes.append(item.get("process"))

        if item.get("pid") not in pids:
            pids.append(item.get("pid"))

    actual_time_range = {
        "start": timeline[0]["time"] if timeline else None,
        "end": timeline[-1]["time"] if timeline else None,
    }

    return {
        "query_plan": investigation or {},
        "event_count": len(selected),
        "final_summary_verdict": summarize_verdict(selected),
        "sources": sources,
        "processes": processes,
        "pids": pids,
        "verdicts": verdicts,
        "attack_chain": phases,
        "actual_event_time_range": actual_time_range,
        "timeline": timeline,
    }