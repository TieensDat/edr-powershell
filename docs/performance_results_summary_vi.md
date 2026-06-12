# Tổng Hợp Kết Quả Đo Hiệu Năng Hệ Thống

Tài liệu này tổng hợp kết quả đo hiệu năng của hệ thống Mini EDR PowerShell trên máy ảo Windows 10 dùng cho thực nghiệm. Các số liệu được nhập lại từ kết quả chạy script đo hiệu năng trong từng ảnh chụp màn hình.

## 1. Mục Tiêu Đo

Mục tiêu của phép đo là đánh giá mức tiêu thụ tài nguyên của hệ thống trong các trạng thái vận hành khác nhau:

- Baseline: máy Windows không chạy agent.
- PythonAgent idle: chỉ chạy PythonAgent, không phát sinh workload đáng kể.
- PythonAgent + C++ Agent idle: chạy đồng thời PythonAgent và AgentConsole.
- Normal workload: mô phỏng thao tác nhẹ hằng ngày trong khi agent đang chạy.
- Attack workload: mô phỏng telemetry đáng nghi bằng synthetic attack workload kết hợp Atomic Red Team.

Các chỉ số chính được theo dõi:

| Chỉ số | Ý nghĩa |
|---|---|
| System CPU Avg (%) | CPU trung bình toàn hệ thống trong thời gian đo. |
| Available Memory Avg (MB) | RAM còn trống trung bình. Chỉ số này chịu ảnh hưởng bởi cache của Windows nên chỉ dùng để tham khảo. |
| Disk Bytes/sec Avg | Lưu lượng I/O trung bình của toàn hệ thống. |
| Python CPU Avg (%) | CPU trung bình của tiến trình PythonAgent. |
| Python Private Memory Avg (MB) | Bộ nhớ private trung bình của PythonAgent. |
| AgentConsole CPU Avg (%) | CPU trung bình của C++ Agent. |
| AgentConsole Private Memory Avg (MB) | Bộ nhớ private trung bình của C++ Agent. |

## 2. Môi Trường Và Quy Ước Đo

Môi trường đo:

| Thành phần | Giá trị |
|---|---|
| Nền tảng ảo hóa | Hyper-V |
| Hệ điều hành VM | Windows 10 |
| vCPU | 4 logical cores |
| RAM VM | 6144 MB |
| Disk VM | tối đa 60 GB |
| Công cụ đo | `scripts/measure_performance.ps1` |
| Normal workload | `scripts/measure_normal_workload.ps1` |
| Attack workload | `scripts/measure_attack_workload.ps1 -Mode Both` |
| Sample interval | 1 giây |

Quy ước tổng hợp:

- Mỗi kịch bản được đo 4 lần liên tiếp.
- `run1` được xem là lần warm-up, dùng để làm nóng hệ thống, cache, tiến trình nền và workload.
- Bảng kết quả từng kịch bản vẫn giữ đủ `run1` đến `run4` để làm bằng chứng thô.
- Kết quả tổng hợp chính chỉ lấy trung bình từ `run2` đến `run4`, nhằm giảm ảnh hưởng của warm-up/cache/I/O ban đầu ở `run1`.
- Khi đưa vào báo cáo chính, sử dụng giá trị trung bình `run2-run4` để nhận xét xu hướng tài nguyên.

## 3. Kịch Bản 1 - Baseline

Trạng thái đo: máy Windows ở trạng thái không chạy PythonAgent và không chạy AgentConsole.

| Lần đo | Thời gian đo | System CPU Avg (%) | Available Memory Avg (MB) | Disk Bytes/sec Avg | Python CPU (%) | AgentConsole CPU (%) |
|---|---:|---:|---:|---:|---:|---:|
| baseline_run1 | 60s | 1.18 | 593.47 | 293428.68 | 0 | 0 |
| baseline_run2 | 60s | 0.46 | 648.17 | 5971.77 | 0 | 0 |
| baseline_run3 | 60s | 0.83 | 671.62 | 9454.40 | 0 | 0 |
| baseline_run4 | 60s | 0.45 | 679.70 | 3266.24 | 0 | 0 |

Tổng hợp chính, tính trung bình từ `run2` đến `run4`:

| Chỉ số | Giá trị trung bình run2-run4 |
|---|---:|
| System CPU Avg (%) | 0.58 |
| Available Memory Avg (MB) | 666.50 |
| Disk Bytes/sec Avg | 6230.80 |

Nhận xét: baseline cho thấy máy ảo ở trạng thái rảnh có CPU hệ thống rất thấp. `baseline_run1` có I/O cao hơn rõ rệt so với các lần sau, nhiều khả năng do hoạt động nền/cache ban đầu của Windows. Vì vậy khi so sánh trạng thái ổn định, nên ưu tiên run2-run4.

## 4. Kịch Bản 2 - PythonAgent Idle

Trạng thái đo: PythonAgent đang chạy, chưa chạy C++ Agent và chưa phát sinh workload chủ động.

| Lần đo | Thời gian đo | System CPU Avg (%) | Disk Bytes/sec Avg | Python CPU Avg (%) | Python Private Memory Avg (MB) |
|---|---:|---:|---:|---:|---:|
| pythonagent_idle_run1 | 60s | 1.11 | 166347.15 | 0.08 | 330.69 |
| pythonagent_idle_run2 | 60s | 0.58 | 31575.76 | 0.08 | 330.76 |
| pythonagent_idle_run3 | 60s | 0.58 | 6919.07 | 0.07 | 330.81 |
| pythonagent_idle_run4 | 60s | 0.50 | 6349.25 | 0.05 | 330.93 |

Tổng hợp chính, tính trung bình từ `run2` đến `run4`:

| Chỉ số | Giá trị trung bình run2-run4 |
|---|---:|
| System CPU Avg (%) | 0.55 |
| Available Memory Avg (MB) | 855.88 |
| Disk Bytes/sec Avg | 14948.03 |
| Python CPU Avg (%) | 0.07 |
| Python Private Memory Avg (MB) | 330.83 |

Nhận xét: khi idle, PythonAgent gần như không tạo tải CPU đáng kể. CPU riêng của PythonAgent chỉ khoảng 0.07%, thấp hơn nhiều so với CPU toàn hệ thống. Bộ nhớ private của PythonAgent ổn định quanh 330-331 MB.

## 5. Kịch Bản 3 - PythonAgent + C++ Agent Idle

Trạng thái đo: PythonAgent và AgentConsole cùng chạy, chưa phát sinh workload chủ động.

| Lần đo | Thời gian đo | System CPU Avg (%) | Disk Bytes/sec Avg | Python CPU Avg (%) | Python Private Memory Avg (MB) | AgentConsole CPU Avg (%) | AgentConsole Private Memory Avg (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| pythonagent_cpp_idle_run1 | 60s | 0.82 | 488349.74 | 0.05 | 330.81 | 0.02 | 1.81 |
| pythonagent_cpp_idle_run2 | 60s | 0.50 | 13686.97 | 0.05 | 331.02 | 0.00 | 1.79 |
| pythonagent_cpp_idle_run3 | 60s | 0.44 | 103352.83 | 0.05 | 331.01 | 0.00 | 1.79 |
| pythonagent_cpp_idle_run4 | 60s | 0.60 | 62873.15 | 0.07 | 331.01 | 0.00 | 1.79 |

Tổng hợp chính, tính trung bình từ `run2` đến `run4`:

| Chỉ số | Giá trị trung bình run2-run4 |
|---|---:|
| System CPU Avg (%) | 0.51 |
| Available Memory Avg (MB) | 999.64 |
| Disk Bytes/sec Avg | 59970.98 |
| Python CPU Avg (%) | 0.06 |
| Python Private Memory Avg (MB) | 331.01 |
| AgentConsole CPU Avg (%) | 0.00 |
| AgentConsole Private Memory Avg (MB) | 1.79 |

Nhận xét: khi thêm C++ Agent ở trạng thái idle, mức tăng tài nguyên rất nhỏ. AgentConsole gần như không tiêu thụ CPU và chỉ dùng khoảng 1.8 MB private memory. PythonAgent vẫn giữ mức bộ nhớ tương đương kịch bản idle trước đó.

## 6. Kịch Bản 4 - Normal Workload

Trạng thái đo: PythonAgent và C++ Agent đang chạy, đồng thời chạy script mô phỏng workload nhẹ hằng ngày.

| Lần đo | Thời gian đo | System CPU Avg (%) | Disk Bytes/sec Avg | Python CPU Avg (%) | Python Private Memory Avg (MB) | AgentConsole CPU Avg (%) | AgentConsole Private Memory Avg (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| normal_workload_run1 | 120s | 0.69 | 13321.59 | 0.02 | 331.12 | 0.00 | 1.75 |
| normal_workload_run2 | 120s | 1.15 | 202396.58 | 0.06 | 331.20 | 0.00 | 1.75 |
| normal_workload_run3 | 120s | 0.60 | 60647.68 | 0.03 | 331.20 | 0.00 | 1.75 |
| normal_workload_run4 | 120s | 1.40 | 264986.70 | 0.08 | 331.23 | 0.00 | 1.75 |

Tổng hợp chính, tính trung bình từ `run2` đến `run4`:

| Chỉ số | Giá trị trung bình run2-run4 |
|---|---:|
| System CPU Avg (%) | 1.05 |
| Available Memory Avg (MB) | 1459.60 |
| Disk Bytes/sec Avg | 176010.32 |
| Python CPU Avg (%) | 0.06 |
| Python Private Memory Avg (MB) | 331.21 |
| AgentConsole CPU Avg (%) | 0.00 |
| AgentConsole Private Memory Avg (MB) | 1.75 |

Nhận xét: workload bình thường làm tăng I/O và CPU toàn hệ thống, nhưng PythonAgent vẫn chỉ tiêu thụ khoảng 0.06% CPU ở trạng thái ổn định. Bộ nhớ private của PythonAgent gần như không tăng so với idle. Điều này cho thấy agent không tạo overhead đáng kể trong workload nhẹ hằng ngày.

## 7. Kịch Bản 5 - Attack Workload

Trạng thái đo: PythonAgent và C++ Agent đang chạy, workload tấn công được chạy ở chế độ `Both`, gồm synthetic attack workload và Atomic Red Team.

| Lần đo | Thời gian đo | System CPU Avg (%) | Disk Bytes/sec Avg | Python CPU Avg (%) | Python Private Memory Avg (MB) | AgentConsole CPU Avg (%) | AgentConsole Private Memory Avg (MB) |
|---|---:|---:|---:|---:|---:|---:|---:|
| attack_both_run1 | 600s | 11.72 | 1325466.88 | 4.36 | 333.01 | 0.95 | 3.00 |
| attack_both_run2 | 600s | 17.40 | 699818.36 | 3.16 | 333.38 | 1.18 | 3.39 |
| attack_both_run3 | 600s | 23.35 | 729972.45 | 3.52 | 333.80 | 1.16 | 3.84 |
| attack_both_run4 | 600s | 16.33 | 281448.57 | 3.26 | 334.00 | 1.16 | 3.95 |

Tổng hợp chính, tính trung bình từ `run2` đến `run4`:

| Chỉ số | Giá trị trung bình run2-run4 |
|---|---:|
| System CPU Avg (%) | 19.03 |
| Available Memory Avg (MB) | 1740.42 |
| Disk Bytes/sec Avg | 570413.13 |
| Python CPU Avg (%) | 3.31 |
| Python Private Memory Avg (MB) | 333.73 |
| AgentConsole CPU Avg (%) | 1.17 |
| AgentConsole Private Memory Avg (MB) | 3.73 |

Nhận xét: attack workload làm tăng CPU toàn hệ thống rõ rệt do phát sinh nhiều telemetry và nhiều lệnh PowerShell/Atomic Red Team. PythonAgent tăng từ khoảng 0.06-0.07% CPU ở idle lên khoảng 3.31% CPU ở trạng thái ổn định. C++ Agent tăng lên khoảng 1.17% CPU. Tuy nhiên, bộ nhớ private của PythonAgent chỉ tăng nhẹ từ khoảng 331 MB lên khoảng 333-334 MB, cho thấy workload chủ yếu làm tăng CPU xử lý telemetry chứ không gây tăng RAM mạnh.

## 8. Bảng Tổng Hợp Cuối

Bảng dưới đây là bảng tổng hợp chính của báo cáo. Tất cả giá trị trong bảng được tính bằng trung bình từ `run2` đến `run4`; `run1` chỉ được giữ trong bảng kết quả từng kịch bản như lần warm-up và không đưa vào trung bình chính.

| Kịch bản | System CPU Avg (%) | Disk Bytes/sec Avg | Python CPU Avg (%) | Python Private Memory Avg (MB) | AgentConsole CPU Avg (%) | AgentConsole Private Memory Avg (MB) |
|---|---:|---:|---:|---:|---:|---:|
| Baseline | 0.58 | 6230.80 | 0.00 | 0.00 | 0.00 | 0.00 |
| PythonAgent idle | 0.55 | 14948.03 | 0.07 | 330.83 | 0.00 | 0.00 |
| PythonAgent + C++ Agent idle | 0.51 | 59970.98 | 0.06 | 331.01 | 0.00 | 1.79 |
| Normal workload | 1.05 | 176010.32 | 0.06 | 331.21 | 0.00 | 1.75 |
| Attack workload | 19.03 | 570413.13 | 3.31 | 333.73 | 1.17 | 3.73 |

## 9. Các Điểm Cần Giải Thích Khi Diễn Giải Kết Quả

Khi trình bày kết quả đo hiệu năng, cần làm rõ một số điểm để tránh diễn giải sai số liệu. Các điểm này không làm mất giá trị của phép đo, nhưng cần được nêu rõ để kết luận có tính khoa học và chặt chẽ hơn.

### 9.1. `run1` Có Nhiễu Warm-Up Rõ

Trong nhiều kịch bản, `run1` có giá trị Disk I/O hoặc CPU khác biệt so với các lần đo sau. Ví dụ ở baseline:

| Lần đo | Disk Bytes/sec Avg |
|---|---:|
| baseline_run1 | 293428.68 |
| baseline_run2 | 5971.77 |
| baseline_run3 | 9454.40 |
| baseline_run4 | 3266.24 |

Sự chênh lệch này cho thấy `run1` chịu ảnh hưởng của quá trình warm-up, bao gồm khởi tạo tiến trình, cache của Windows, hoạt động nền, cập nhật trạng thái file system hoặc dịch vụ hệ thống. Vì vậy, `run1` được giữ lại như dữ liệu thô để minh bạch, nhưng không đưa vào bảng tổng hợp chính. Bảng tổng hợp chính sử dụng trung bình `run2-run4`, phản ánh trạng thái ổn định hơn của hệ thống.

### 9.2. Disk I/O Dao Động Mạnh

Chỉ số `Disk Bytes/sec Avg` biến động mạnh giữa các lần đo, kể cả trong các kịch bản không thay đổi nhiều về CPU. Điều này có thể đến từ nhiều nguyên nhân không hoàn toàn thuộc về agent:

- Windows cache và cơ chế lazy write.
- Dịch vụ nền của Windows hoặc Windows Defender.
- Hoạt động ghi log của PowerShell, PythonAgent hoặc Atomic Red Team.
- Cơ chế lưu trữ của Hyper-V và trạng thái đĩa ảo.
- Sự khác biệt về số lượng event/log phát sinh trong từng lần chạy workload.

Vì vậy, Disk I/O nên được dùng như chỉ số tham khảo để quan sát xu hướng tải hệ thống, không nên dùng làm chỉ số duy nhất để kết luận overhead của agent. Trong báo cáo, kết luận chính nên dựa nhiều hơn vào CPU riêng của PythonAgent, CPU riêng của AgentConsole và private memory của từng tiến trình.

### 9.3. Available Memory Không Nên Dùng Để Kết Luận Overhead RAM

`Available Memory AvgMB` phản ánh lượng RAM còn trống của toàn hệ thống, nhưng trên Windows chỉ số này không đồng nghĩa trực tiếp với RAM mà agent đang tiêu thụ. Windows có thể dùng RAM trống cho cache, sau đó thu hồi khi ứng dụng cần. Vì vậy, Available Memory có thể tăng/giảm do cache và dịch vụ nền, không chỉ do PythonAgent hoặc C++ Agent.

Để đánh giá overhead RAM của agent, các chỉ số phù hợp hơn là:

- `PythonPrivateMemoryAvgMB`
- `AgentConsolePrivateMemoryAvgMB`

Kết quả đo cho thấy private memory của PythonAgent khá ổn định:

| Kịch bản | Python Private Memory Avg (MB), run2-run4 |
|---|---:|
| PythonAgent idle | 330.83 |
| PythonAgent + C++ Agent idle | 331.01 |
| Normal workload | 331.21 |
| Attack workload | 333.73 |

Mức tăng từ idle sang attack workload chỉ khoảng 2-3 MB, chưa cho thấy dấu hiệu tăng RAM bất thường hoặc memory leak trong phạm vi đo hiện tại.

### 9.4. Attack Workload CPU Tăng Mạnh Nhưng Hợp Lý

Attack workload có mức CPU cao hơn rõ rệt so với idle và normal workload:

| Kịch bản | System CPU Avg (%) | Python CPU Avg (%) | AgentConsole CPU Avg (%) |
|---|---:|---:|---:|
| PythonAgent + C++ Agent idle | 0.51 | 0.06 | 0.00 |
| Normal workload | 1.05 | 0.06 | 0.00 |
| Attack workload | 19.03 | 3.31 | 1.17 |

Sự tăng này là hợp lý vì attack workload tạo ra nhiều telemetry đáng nghi, nhiều lệnh PowerShell, nhiều event từ Atomic Red Team và nhiều nội dung cần trích xuất đặc trưng G2.96. Do đó, CPU tăng phản ánh agent đang thực sự xử lý dữ liệu đầu vào, không phải dấu hiệu bất thường. Điểm quan trọng là dù CPU tăng, private memory của PythonAgent vẫn ổn định quanh 333-334 MB.

### 9.5. Normal Workload Gần Như Không Làm PythonAgent Tăng CPU

Trong normal workload, PythonAgent CPU trung bình vẫn khoảng 0.06%, gần tương đương trạng thái idle. Điều này phù hợp với thiết kế hiện tại vì normal workload chỉ mô phỏng thao tác nhẹ hằng ngày và không tạo nhiều telemetry đáng nghi cần phân tích sâu.

Kết quả này cho thấy trong điều kiện workload nhẹ, agent không tạo overhead CPU đáng kể. Tuy nhiên, cần ghi rõ rằng normal workload hiện tại chưa bao gồm các hoạt động nặng như duyệt web nhiều tab, Microsoft Office, copy dữ liệu lớn hoặc chạy nhiều script quản trị hợp lệ cùng lúc.

## 10. Đánh Giá Chung

Từ các kết quả đo, có thể rút ra các nhận xét chính:

1. Ở trạng thái idle, PythonAgent có overhead CPU rất thấp, khoảng 0.06-0.07%.
2. C++ Agent ở trạng thái idle gần như không tạo tải CPU đáng kể và chỉ dùng khoảng 1.8 MB private memory.
3. Trong normal workload, CPU của PythonAgent vẫn quanh 0.06%, cho thấy agent không ảnh hưởng đáng kể tới thao tác nhẹ hằng ngày trong môi trường lab.
4. Trong attack workload, CPU của PythonAgent tăng lên khoảng 3.31% và C++ Agent tăng lên khoảng 1.17%, phù hợp vì hệ thống phải xử lý nhiều telemetry đáng nghi.
5. RAM của PythonAgent ổn định quanh 331 MB ở idle/normal workload và chỉ tăng lên khoảng 333-334 MB trong attack workload. Điều này cho thấy hệ thống không có dấu hiệu tăng bộ nhớ bất thường trong các phép đo hiện tại.
6. I/O toàn hệ thống dao động khá mạnh giữa các lần đo, đặc biệt ở run1 hoặc khi chạy workload. Vì vậy Disk Bytes/sec nên được dùng như chỉ số tham khảo, không nên là chỉ số kết luận duy nhất.

## 11. Kết Luận

Kết quả đo hiệu năng cho thấy hệ thống Mini EDR PowerShell ở mức prototype/lab có mức tiêu thụ tài nguyên hợp lý. Trong trạng thái idle và workload bình thường, CPU của PythonAgent và C++ Agent rất thấp. Khi chạy attack workload, tài nguyên tăng lên rõ rệt nhưng vẫn nằm trong mức chấp nhận được đối với máy ảo 4 vCPU, đặc biệt vì đây là giai đoạn agent phải xử lý nhiều telemetry PowerShell đáng nghi.

Do đó, có thể kết luận rằng hệ thống hiện tại đủ điều kiện để trình bày trong khóa luận như một prototype EDR chạy ngầm trong môi trường lab, với overhead thấp ở trạng thái bình thường và có mức tăng tài nguyên hợp lý khi xử lý workload tấn công.

## 12. Hạn Chế Của Phép Đo

- Số liệu được ghi nhận từ máy ảo Hyper-V, chưa đại diện hoàn toàn cho máy vật lý hoặc môi trường doanh nghiệp.
- Kết quả được tổng hợp từ ảnh chụp màn hình, chưa phải từ file CSV tự động hóa đầy đủ.
- Số lần đo là 4 lần mỗi kịch bản, phù hợp cho báo cáo khóa luận nhưng chưa đủ cho benchmark thống kê chuyên sâu.
- Workload bình thường chỉ mô phỏng thao tác nhẹ, chưa bao gồm trình duyệt web nặng, Microsoft Office hoặc copy dữ liệu lớn.
- Attack workload dùng synthetic attack và Atomic Red Team selected tests, chưa đại diện cho toàn bộ kỹ thuật tấn công thực tế.
- Disk I/O có độ dao động cao do Windows cache, background service và trạng thái VM.
