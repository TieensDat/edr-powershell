# Mermaid cho phần kiến trúc và pipeline trong báo cáo Word

Tài liệu này chứa các sơ đồ Mermaid đã được tối ưu để chèn vào Word theo bố cục dọc. Thay vì dùng một sơ đồ quá lớn, phần kiến trúc nên chia thành 3 hình nhỏ:

1. Kiến trúc tổng quan hệ thống.
2. Pipeline xử lý trong PythonAgent.
3. Cơ chế response theo nguồn telemetry.

Cách trình bày này giúp giáo viên hướng dẫn nắm hệ thống theo từng lớp: hệ thống nhận dữ liệu từ đâu, PythonAgent xử lý như thế nào, và response được quyết định ra sao.

## Hình 1. Kiến trúc tổng quan hệ thống Mini EDR PowerShell

```mermaid
flowchart TB
    A["Windows Endpoint Lab<br/>PowerShell / JS / BAT / CMD / EXE"] --> B["Nguồn telemetry"]

    B --> B1["File System<br/>script files"]
    B --> B2["Process Table<br/>PID, PPID, command line"]
    B --> B3["Event Log 4104<br/>Script Block Logging"]
    B --> B4["Windows AMSI<br/>runtime script content"]

    B4 --> C1["AmsiProvider.dll<br/>Custom AMSI Provider"]
    C1 --> C2["Named Pipe<br/>EdrAmsiPipe"]
    C2 --> C3["AgentConsole.exe<br/>C++ Bridge Agent"]
    C3 --> C4["C++ Local Rules<br/>quick verdict"]

    B1 --> D["PythonAgent<br/>central analysis engine"]
    B2 --> D
    B3 --> D
    C3 --> D

    D --> E["Detection<br/>G2.96 Features + Rules + ML"]
    E --> F["Final Verdict<br/>ALLOW / ALERT / TERMINATE"]
    F --> G["Response Engine<br/>opt-in, source-aware"]
    G --> H["Evidence Logs & Reports<br/>JSONL / CSV / Test Reports"]

    H --> I["ReportChatAgent<br/>log correlation & report support"]

    classDef source fill:#E8F1FF,stroke:#2F5F9F,stroke-width:1px,color:#111;
    classDef native fill:#FFF1D6,stroke:#A66A00,stroke-width:1px,color:#111;
    classDef python fill:#EAF7EA,stroke:#2E7D32,stroke-width:1px,color:#111;
    classDef output fill:#F2EAFE,stroke:#6A3FA0,stroke-width:1px,color:#111;

    class B,B1,B2,B3,B4 source;
    class C1,C2,C3,C4 native;
    class D,E,F,G python;
    class H,I output;
```

**Cách giải thích với giáo viên hướng dẫn:**

Sơ đồ này mô tả toàn bộ hệ thống theo 4 lớp. Lớp đầu tiên là endpoint Windows, nơi phát sinh hành vi PowerShell hoặc script. Lớp thứ hai là các nguồn telemetry gồm file, process, Event Log 4104 và AMSI. Lớp thứ ba là PythonAgent, đóng vai trò trung tâm phân tích và kết hợp rule, ML, risk score. Lớp cuối cùng là response, log bằng chứng và ReportChatAgent hỗ trợ điều tra.

**Chú thích hình đề xuất:**

```text
Hình x. Kiến trúc tổng quan hệ thống Mini EDR PowerShell.
```

## Hình 2. Pipeline xử lý telemetry trong PythonAgent

```mermaid
flowchart TB
    A["Telemetry Event<br/>file / process / 4104 / AMSI"] --> B["Normalize Event<br/>source, pid, process, path, script"]
    B --> C["Noise Filter<br/>bỏ event rỗng, health check, module noise"]
    C --> D["Dedup<br/>hash script content"]
    D --> E["Feature Extraction G2.96"]

    E --> E1["Raw Features<br/>length, entropy, line count"]
    E --> E2["Payload Features<br/>Base64, URL, IP, domain"]
    E --> E3["Obfuscation Features<br/>EncodedCommand, join, replace, char array"]
    E --> E4["Behavior Features<br/>IEX, download, registry, Defender tampering"]

    E1 --> F["Detection Engine"]
    E2 --> F
    E3 --> F
    E4 --> F

    F --> F1["Risk Analysis<br/>risk_score, reasons"]
    F --> F2["Rule Detection<br/>ALLOW / ALERT / TERMINATE"]
    F --> F3["ML Inference<br/>Random Forest model"]

    F1 --> G["Verdict Combination"]
    F2 --> G
    F3 --> G

    G --> H["Final Verdict<br/>ALLOW / ALERT / TERMINATE"]
    H --> I["Event Queue + Worker"]
    I --> J["Response Engine"]
    I --> K["Evidence Logs<br/>edr_events.jsonl<br/>edr_features_g296.csv"]

    classDef input fill:#E8F1FF,stroke:#2F5F9F,stroke-width:1px,color:#111;
    classDef process fill:#EAF7EA,stroke:#2E7D32,stroke-width:1px,color:#111;
    classDef feature fill:#FFF1D6,stroke:#A66A00,stroke-width:1px,color:#111;
    classDef detect fill:#F2EAFE,stroke:#6A3FA0,stroke-width:1px,color:#111;
    classDef output fill:#FCE8E8,stroke:#B3261E,stroke-width:1px,color:#111;

    class A input;
    class B,C,D,I process;
    class E,E1,E2,E3,E4 feature;
    class F,F1,F2,F3,G,H detect;
    class J,K output;
```

**Cách giải thích với giáo viên hướng dẫn:**

Sơ đồ này tập trung vào bên trong PythonAgent. Mọi telemetry từ các sensor đều được chuẩn hóa về cùng định dạng, sau đó lọc nhiễu và chống trùng lặp. Nội dung script hoặc command line được trích xuất đặc trưng G2.96. Detection Engine kết hợp ba nguồn quyết định: risk analysis, rule-based detection và Machine Learning. Cuối cùng agent tạo final verdict và ghi log bằng chứng.

**Chú thích hình đề xuất:**

```text
Hình x. Pipeline xử lý telemetry trong PythonAgent.
```

## Hình 3. Response theo nguồn telemetry

```mermaid
flowchart TB
    A["Final Verdict"] --> B{"Verdict = TERMINATE?"}

    B -- "Không" --> C["Không response<br/>chỉ ghi log"]
    B -- "Có" --> D{"EDR_ENABLE_RESPONSE = 1?"}

    D -- "Không" --> E["Response disabled<br/>ghi response_reason"]
    D -- "Có" --> F{"Nguồn telemetry"}

    F -- "process_sensor" --> G["Kiểm tra protected process<br/>và protected command line"]
    G --> H["Terminate Process<br/>nếu PID tin cậy"]

    F -- "file_sensor" --> I["Kiểm tra file thuộc watch path"]
    I --> J["Quarantine File<br/>di chuyển vào PythonAgent/quarantine"]

    F -- "eventlog_4104_sensor" --> K["LOG_ONLY<br/>không kill vì thiếu PID tin cậy"]

    F -- "amsi_cpp_bridge" --> L["DELEGATED_TO_CPP_AGENT<br/>C++ Agent xử lý gần AMSI/PID hơn"]

    H --> M["Evidence Log"]
    J --> M
    K --> M
    L --> M
    E --> M
    C --> M

    M --> N["edr_events.jsonl<br/>quarantine_index.jsonl<br/>response_action / reason"]

    classDef decision fill:#FFF1D6,stroke:#A66A00,stroke-width:1px,color:#111;
    classDef action fill:#EAF7EA,stroke:#2E7D32,stroke-width:1px,color:#111;
    classDef log fill:#E8F1FF,stroke:#2F5F9F,stroke-width:1px,color:#111;
    classDef stop fill:#FCE8E8,stroke:#B3261E,stroke-width:1px,color:#111;

    class B,D,F decision;
    class G,H,I,J,K,L action;
    class M,N log;
    class C,E stop;
```

**Cách giải thích với giáo viên hướng dẫn:**

Sơ đồ này giải thích vì sao response của hệ thống không xử lý giống nhau cho mọi event. Agent chỉ response khi verdict là `TERMINATE` và biến môi trường `EDR_ENABLE_RESPONSE` được bật. Với `process_sensor`, agent có thể terminate process nếu PID tin cậy. Với `file_sensor`, agent quarantine file nếu file nằm trong watch path. Với `eventlog_4104_sensor`, agent chỉ log vì Event Log 4104 không cung cấp PID đủ tin cậy. Với `amsi_cpp_bridge`, response được giao cho C++ Agent vì thành phần này gần tầng AMSI và PID runtime hơn.

**Chú thích hình đề xuất:**

```text
Hình x. Cơ chế response theo nguồn telemetry trong PythonAgent.
```

## Cách xuất sơ đồ để chèn vào Word

Có thể dùng một trong các cách sau:

1. Mở file `.md` bằng VS Code có hỗ trợ Mermaid Preview.
2. Copy từng block Mermaid vào Mermaid Live Editor.
3. Export hình ở định dạng `SVG` hoặc `PNG`.
4. Chèn hình vào Word bằng `Insert -> Pictures`.
5. Đặt caption theo mẫu:

```text
Hình x. Tên sơ đồ
Nguồn: Nhóm thực hiện
```

Gợi ý khi chèn vào Word:

- Dùng sơ đồ dọc để phù hợp trang A4 portrait.
- Nếu sơ đồ vẫn dài, đặt mỗi sơ đồ ở một trang riêng.
- Nên dùng `SVG` nếu Word hỗ trợ để hình không bị vỡ.
- Nếu dùng `PNG`, nên export ở độ phân giải cao.
- Không cần đưa toàn bộ chi tiết code vào hình, chỉ giữ các khối chính để giáo viên nắm nhanh kiến trúc.

