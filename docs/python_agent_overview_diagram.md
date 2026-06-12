# Sơ đồ kiến trúc tổng quan PythonAgent

Tài liệu này dùng để trực quan hóa kiến trúc hiện tại của `PythonAgent` trong hệ thống Mini EDR PowerShell. Sơ đồ tập trung vào luồng chính: thu thập telemetry, chuẩn hóa dữ liệu, trích xuất đặc trưng, phát hiện, response và ghi log bằng chứng.

## 1. Sơ đồ tổng quan

```mermaid
flowchart LR
    subgraph S["Nguồn telemetry"]
        FS["File Sensor<br/>Theo dõi .ps1, .js, .bat, .cmd..."]
        PS["Process Sensor<br/>Thu command line, PID, PPID"]
        EV["Event Log 4104 Sensor<br/>PowerShell ScriptBlockText"]
        AMSI["C++ AMSI Bridge<br/>POST /telemetry"]
    end

    subgraph PA["PythonAgent"]
        API["Flask API<br/>/telemetry, /health, /reload-model"]
        NORMALIZE["Chuẩn hóa event<br/>source, pid, process, path, script"]
        FILTER["Noise filter + dedup<br/>bỏ event rỗng, health check, module noise"]
        FEATURES["Feature Extraction G2.96<br/>raw, payload, obfuscation, behavior"]
        ANALYSIS["Data Analysis<br/>risk_score, risk_level, reasons"]
        RULE["Rule-based Detection<br/>ALLOW / ALERT / TERMINATE"]
        ML["ML Inference<br/>Random Forest .pkl"]
        COMBINE["Verdict Combination<br/>final_verdict"]
        QUEUE["Event Queue + Worker"]
    end

    subgraph RESP["Response Engine"]
        CHECK["Opt-in check<br/>EDR_ENABLE_RESPONSE"]
        SOURCE["Source-aware action"]
        KILL["Terminate process<br/>process_sensor"]
        QUAR["Quarantine file<br/>file_sensor"]
        LOGONLY["Log only<br/>eventlog_4104_sensor"]
        CPP["Delegate to C++ Agent<br/>amsi_cpp_bridge"]
        PROTECT["Protected list<br/>process/path guard"]
    end

    subgraph OUT["Bằng chứng đầu ra"]
        JSONL["edr_events.jsonl"]
        CSV["edr_features_g296.csv"]
        QINDEX["quarantine_index.jsonl"]
        QDIR["PythonAgent/quarantine/"]
        REPORTS["test reports JSON"]
    end

    FS --> NORMALIZE
    PS --> NORMALIZE
    EV --> NORMALIZE
    AMSI --> API --> NORMALIZE

    NORMALIZE --> FILTER --> FEATURES
    FEATURES --> ANALYSIS
    FEATURES --> RULE
    FEATURES --> ML
    ANALYSIS --> COMBINE
    RULE --> COMBINE
    ML --> COMBINE
    COMBINE --> QUEUE
    QUEUE --> CHECK

    CHECK --> SOURCE
    SOURCE --> PROTECT
    PROTECT --> KILL
    PROTECT --> QUAR
    SOURCE --> LOGONLY
    SOURCE --> CPP

    QUEUE --> JSONL
    QUEUE --> CSV
    QUAR --> QINDEX
    QUAR --> QDIR
    JSONL --> REPORTS
```

## 2. Pipeline xử lý một event

```mermaid
sequenceDiagram
    participant Source as Telemetry Source
    participant Agent as PythonAgent
    participant Feature as Feature Extraction G2.96
    participant Detect as Rule/ML Detection
    participant Resp as Response Engine
    participant Logs as Evidence Logs

    Source->>Agent: Gửi event chứa script / command line / ScriptBlockText
    Agent->>Agent: Chuẩn hóa event
    Agent->>Agent: Lọc noise và dedup theo hash
    Agent->>Feature: Trích xuất đặc trưng G2.96
    Feature-->>Agent: Feature vector
    Agent->>Detect: Rule detection + ML inference
    Detect-->>Agent: rule_verdict, ml_verdict, risk_level
    Agent->>Agent: Kết hợp verdict thành final_verdict
    Agent->>Resp: Chỉ response nếu final_verdict = TERMINATE
    Resp-->>Agent: response_action, response_success, response_reason
    Agent->>Logs: Ghi edr_events.jsonl và edr_features_g296.csv
```

## 3. Vai trò các khối chính

| Khối | Vai trò |
|---|---|
| File Sensor | Theo dõi file script trong Desktop, Downloads, Documents và OneDrive tương ứng |
| Process Sensor | Ghi nhận process mới, command line, PID, PPID và parent process |
| Event Log 4104 Sensor | Đọc PowerShell Script Block Logging từ Windows Event Log |
| C++ AMSI Bridge | Gửi nội dung script runtime từ AMSI sang PythonAgent qua HTTP |
| Feature Extraction G2.96 | Chuyển script/command thành vector đặc trưng hành vi |
| Rule Detection | Phát hiện nhanh các indicator như EncodedCommand, IEX, downloader, bypass, Defender tampering |
| ML Inference | Dự đoán `BENIGN`, `SUSPICIOUS` hoặc `MALICIOUS` nếu model được load |
| Verdict Combination | Kết hợp C++ verdict, rule verdict, ML verdict và risk level |
| Response Engine | Response opt-in, chỉ xử lý `TERMINATE`, phân biệt hành động theo source |
| Evidence Logs | Lưu event, feature, response action và report phục vụ thực nghiệm |

## 4. Gợi ý chèn vào báo cáo

Tên hình đề xuất:

```text
Hình 3.x. Kiến trúc tổng quan của PythonAgent trong hệ thống Mini EDR PowerShell
```

Chú thích ngắn:

```text
PythonAgent đóng vai trò trung tâm phân tích, nhận telemetry từ File Sensor, Process Sensor, Event Log 4104 Sensor và C++ AMSI Bridge. Dữ liệu được chuẩn hóa, trích xuất đặc trưng G2.96, phân loại bằng rule-based detection và Machine Learning, sau đó đưa ra final verdict và ghi log bằng chứng. Response Engine chỉ hoạt động khi được bật và chỉ xử lý các event có verdict TERMINATE.
```

