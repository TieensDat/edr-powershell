MINI EDR POWERSHELL - GÓI RUNTIME

1. Mục đích

Gói runtime này dùng để chạy hệ thống Mini EDR PowerShell trên máy Windows test hoặc máy ảo đo hiệu năng. Gói này chỉ chứa các thành phần cần thiết để vận hành agent, không bao gồm source code dùng để build, tài liệu phát triển, test suite, thư mục .git, log cũ hoặc file đã quarantine trước đó.

Thành phần trong gói:
- PythonAgent: mã PythonAgent, requirements.txt, model ML, thư mục logs rỗng và quarantine rỗng.
- bin: AgentConsole.exe và AmsiProvider.dll.
- scripts: các script setup, start, stop, kiểm tra trạng thái, đăng ký và hủy đăng ký AMSI Provider.
- README_RUNTIME.txt: tài liệu hướng dẫn chạy gói runtime.

2. Yêu cầu cần có trên máy test

Máy test nên là Windows 10/11 64-bit, ưu tiên chạy trong máy ảo có snapshot/checkpoint để dễ hoàn nguyên môi trường.

Bắt buộc:
- Windows 10/11 64-bit.
- Python 3.10 trở lên.
- Python phải được thêm vào PATH.
- pip phải hoạt động.
- PowerShell mặc định của Windows.
- Kết nối Internet nếu cần cài thư viện Python từ requirements.txt.

Nên cài thêm:
- PowerShell 7, nếu muốn chạy lại Atomic Red Team hoặc các script dùng pwsh.
- Microsoft Visual C++ Redistributable 2015-2022 x64, để AgentConsole.exe và AmsiProvider.dll có đủ runtime DLL.

Cần quyền Administrator khi:
- Bật PowerShell Script Block Logging để thu Event Log 4104.
- Đăng ký hoặc hủy đăng ký AmsiProvider.dll bằng regsvr32.
- Một số bài test có hành vi mô phỏng tấn công yêu cầu quyền cao hơn.

3. Kiểm tra môi trường trước khi setup

Mở PowerShell tại thư mục đã giải nén gói runtime và chạy:

python --version
python -m pip --version
powershell -NoProfile -Command "$PSVersionTable.PSVersion"

Nếu có PowerShell 7, kiểm tra thêm:

pwsh --version

Kết quả mong muốn:
- python --version hiển thị Python 3.10 hoặc cao hơn.
- python -m pip --version hiển thị phiên bản pip.
- PowerShell chạy được lệnh script.

Nếu lệnh python không chạy, cần cài Python 3.10+ và chọn tùy chọn "Add Python to PATH" khi cài.

4. Cài đặt runtime

Sau khi giải nén gói zip, mở PowerShell tại thư mục gốc của gói runtime, ví dụ:

C:\KLTN\mini-edr-powershell-runtime

Chạy lệnh:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_runtime.ps1

Script này sẽ:
- Tạo thư mục PythonAgent\logs nếu chưa có.
- Tạo thư mục PythonAgent\quarantine nếu chưa có.
- Cài các thư viện Python từ PythonAgent\requirements.txt.

Lưu ý: script setup_runtime.ps1 không tự cài Python, PowerShell 7 hoặc Visual C++ Redistributable. Các thành phần này cần được cài trước nếu máy test chưa có.

5. Bật Event Log 4104 cho PowerShell Script Block Logging

Nếu cần dùng eventlog_4104_sensor, mở PowerShell bằng quyền Administrator và chạy:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\setup_runtime.ps1 -SkipPipInstall -EnableScriptBlockLogging

Sau đó có thể kiểm tra nhanh bằng:

Invoke-RestMethod http://127.0.0.1:9001/health

Trường eventlog_4104_sensor sẽ là true nếu PythonAgent đang chạy và pywin32 đã được cài đúng.

6. Chạy PythonAgent

Tại thư mục gốc của gói runtime, chạy:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_python_agent.ps1 -Force

Kiểm tra agent:

Invoke-RestMethod http://127.0.0.1:9001/health

Kết quả mong muốn:
- status = running
- feature_version = G2.96
- process_sensor = true nếu psutil hoạt động
- file_sensor = true nếu watchdog hoạt động
- eventlog_4104_sensor = true nếu pywin32 và Event Log 4104 hoạt động

7. Chạy AMSI Bridge

AMSI Bridge dùng khi cần chứng minh luồng end-to-end từ Windows AMSI -> AmsiProvider.dll -> AgentConsole.exe -> PythonAgent.

Mở PowerShell bằng quyền Administrator và đăng ký AmsiProvider.dll:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\register_amsi_provider.ps1

Sau đó chạy C++ Agent:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_cpp_agent.ps1

Khi không dùng nữa, có thể hủy đăng ký AMSI Provider bằng PowerShell Administrator:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\unregister_amsi_provider.ps1

8. Bật response thật khi cần kiểm thử

Mặc định response thật bị tắt để tránh ảnh hưởng ngoài ý muốn trong quá trình đo hiệu năng.

Nếu cần bật response, đặt biến môi trường trước khi start PythonAgent:

$env:EDR_ENABLE_RESPONSE = "1"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_python_agent.ps1 -Force

Cơ chế response hiện tại:
- Chỉ xử lý khi final_verdict là TERMINATE.
- Phân biệt theo source telemetry.
- Không kill tiến trình từ eventlog_4104_sensor do thiếu PID tin cậy.
- Quarantine chỉ áp dụng với file nằm trong watch path và không thuộc protected list.
- Ghi log bằng chứng vào PythonAgent\logs.

9. Dừng agent

Dừng PythonAgent:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop_python_agent.ps1

Dừng C++ Agent:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\stop_cpp_agent.ps1

10. Log và bằng chứng sau khi chạy

Các file cần kiểm tra sau khi chạy:

PythonAgent\logs\edr_events.jsonl
PythonAgent\logs\edr_features_g296.csv
PythonAgent\logs\response_actions.jsonl
PythonAgent\quarantine

Ý nghĩa:
- edr_events.jsonl: log telemetry, feature, verdict và kết quả phân tích.
- edr_features_g296.csv: bảng feature phục vụ đánh giá và phân tích ML.
- response_actions.jsonl: log hành động response nếu response được bật.
- quarantine: nơi lưu file bị cách ly nếu response thực hiện quarantine.

11. Gợi ý dùng cho đo hiệu năng

Nên đo theo các trạng thái:
- Baseline: máy không chạy agent.
- Agent idle: PythonAgent chạy nhưng không có test.
- Agent monitoring: chạy file/process/event sensor với workload bình thường.
- Agent under test: chạy Atomic Red Team hoặc workload mô phỏng tấn công.
- Agent with response: bật response để đo thêm tác động của hành động quarantine/terminate.

Thông số nên thu thập:
- CPU usage của python.exe.
- RAM usage của python.exe.
- Disk IO khi file_sensor hoạt động.
- Số lượng event ghi vào log.
- Detection latency nếu có timestamp đầu vào và timestamp ghi log.
- Response time nếu bật response.

12. Checkpoint và quy trình đo hiệu năng đề xuất

Trong trường hợp máy host chỉ còn khoảng 80 GB trống, không nên tạo quá nhiều checkpoint vì mỗi checkpoint có thể làm tăng dung lượng ổ đĩa ảo. Nên giữ số lượng checkpoint ở mức tối thiểu và xóa checkpoint không còn cần thiết sau khi đã lưu kết quả.

12.1. Nguyên tắc tối ưu dung lượng

- Chỉ giữ 3 đến 4 checkpoint chính.
- Không tạo checkpoint sau khi log/test đã sinh quá nhiều dữ liệu.
- Trước khi tạo checkpoint, nên dừng agent và dọn log nếu không cần giữ bằng chứng trong VM.
- File log, report và ảnh chụp kết quả nên copy ra máy host hoặc thư mục chia sẻ thay vì giữ toàn bộ trong VM.
- Sau khi hoàn thành một nhóm đo, lưu kết quả ra ngoài VM rồi xóa checkpoint trung gian nếu không cần quay lại.

12.2. Các thời điểm cần tạo checkpoint

Checkpoint 1: CP01_Runtime_Installed_Agent_Stopped

Tạo sau khi:
- Đã cài Python 3.10+.
- Đã add Python vào PATH.
- Đã giải nén gói runtime.
- Đã chạy setup_runtime.ps1 thành công.
- PythonAgent và C++ Agent đang tắt.

Đây là checkpoint quan trọng nhất. Dùng checkpoint này để đo baseline và quay lại trạng thái sạch trước mỗi nhóm test.

Checkpoint 2: CP02_PythonAgent_Health_OK

Tạo sau khi:
- Start PythonAgent thành công.
- Lệnh health trả về status = running.
- Chưa chạy workload hoặc Atomic test.

Checkpoint này dùng để đo trạng thái agent idle.

Checkpoint 3: CP03_PythonAgent_CPPAgent_OK

Tạo sau khi:
- PythonAgent chạy ổn định.
- AgentConsole.exe chạy ổn định.
- Nếu cần, AmsiProvider.dll đã được đăng ký thành công.
- Health của PythonAgent vẫn OK.

Checkpoint này dùng để đo trạng thái hệ thống có cả PythonAgent và AMSI bridge.

Checkpoint 4: CP04_Before_Response_Test

Tạo trước khi bật response thật:
- Đảm bảo PythonAgent và C++ Agent đang tắt.
- Dọn log nếu không cần giữ log cũ.
- Chưa đặt hoặc chưa bật EDR_ENABLE_RESPONSE=1.

Checkpoint này dùng để quay lại nhanh nếu response quarantine file hoặc terminate process trong quá trình thử nghiệm.

Nếu dung lượng host quá hạn chế, có thể chỉ giữ CP01 và CP04. Các trạng thái CP02, CP03 có thể thiết lập lại thủ công bằng script start/stop.

12.3. Quy trình đo hiệu năng từng bước

Bước 1: Chuẩn bị chung trước mọi lần đo

- Restore về CP01_Runtime_Installed_Agent_Stopped.
- Đợi Windows ổn định sau khi boot khoảng 3 đến 5 phút.
- Đảm bảo PythonAgent và C++ Agent chưa chạy.
- Ghi nhận cấu hình VM: số CPU, RAM, dung lượng ổ đĩa, phiên bản Windows.
- Đóng các ứng dụng không cần thiết.
- Tạm dừng thao tác người dùng trong lúc script đo đang chạy.
- Dùng cùng một thời lượng đo cho các trạng thái để dễ so sánh. Khuyến nghị: 60 giây cho idle/baseline, 120 giây nếu workload kéo dài.

Script đo hiệu năng dùng chung:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label <TEN_LAN_DO> -DurationSeconds 60 -SampleIntervalSeconds 1

Các giá trị nên ghi ra giấy từ phần Summary:
- SystemCpuAvgPercent
- AvailableMemoryAvgMB
- DiskBytesPerSecAvg
- PythonCpuAvgPercent
- PythonWorkingSetAvgMB
- PythonPrivateMemoryAvgMB
- AgentConsoleCpuAvgPercent
- AgentConsoleWorkingSetAvgMB
- AgentConsolePrivateMemoryAvgMB

Bước 2: Đo baseline

Mục tiêu: đo mức sử dụng tài nguyên của máy khi chưa chạy agent.

Checkpoint sử dụng:
- CP01_Runtime_Installed_Agent_Stopped

Trạng thái:
- PythonAgent: tắt.
- AgentConsole.exe: tắt.
- Response: tắt.

Trước khi đo:
- Restore về CP01.
- Đợi Windows ổn định 3 đến 5 phút sau khi boot.
- Không mở thêm ứng dụng khác.

Lệnh đo:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label baseline_run1 -DurationSeconds 60 -SampleIntervalSeconds 1

Đo lặp lại:
- Sau khi run1 xong, đợi 60 giây.
- Chạy baseline_run2.
- Đợi tiếp 60 giây.
- Chạy baseline_run3.

Lệnh mẫu:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label baseline_run2 -DurationSeconds 60 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label baseline_run3 -DurationSeconds 60 -SampleIntervalSeconds 1

Sau khi đo:
- Ghi 3 bộ số liệu ra giấy.
- Tính trung bình thủ công cho từng cột.
- Không cần restore lại nếu chỉ đo baseline liên tiếp và không thay đổi trạng thái máy.

Ghi chú trong báo cáo:
Baseline được đo sau khi đã cài runtime dependency nhưng chưa khởi chạy agent. Cách đo này nhằm cô lập tác động khi agent hoạt động.

Bước 3: Đo PythonAgent idle

Checkpoint sử dụng:
- Có thể restore về CP01 rồi start PythonAgent thủ công.
- Nếu đã có CP02_PythonAgent_Health_OK thì restore về CP02 để tiết kiệm thời gian.

- Start PythonAgent:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_python_agent.ps1 -Force

- Kiểm tra health:

Invoke-RestMethod http://127.0.0.1:9001/health

- Đợi 1 đến 2 phút cho agent ổn định.
- Đo lần 1:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label pythonagent_idle_run1 -DurationSeconds 60 -SampleIntervalSeconds 1

- Đợi 60 giây rồi đo lần 2:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label pythonagent_idle_run2 -DurationSeconds 60 -SampleIntervalSeconds 1

- Đợi 60 giây rồi đo lần 3:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label pythonagent_idle_run3 -DurationSeconds 60 -SampleIntervalSeconds 1

Sau khi đo:
- Ghi CPU/RAM/IO của python.exe.
- So sánh với baseline để thấy overhead khi chỉ chạy PythonAgent.

Bước 4: Đo PythonAgent + C++ Agent idle

Checkpoint sử dụng:
- Có thể dùng CP02 rồi start C++ Agent.
- Nếu đã có CP03_PythonAgent_CPPAgent_OK thì restore về CP03.

- Start C++ Agent:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_cpp_agent.ps1

- Đợi 1 đến 2 phút cho AgentConsole ổn định.
- Đo lần 1:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label pythonagent_cpp_idle_run1 -DurationSeconds 60 -SampleIntervalSeconds 1

- Đợi 60 giây rồi đo lần 2:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label pythonagent_cpp_idle_run2 -DurationSeconds 60 -SampleIntervalSeconds 1

- Đợi 60 giây rồi đo lần 3:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label pythonagent_cpp_idle_run3 -DurationSeconds 60 -SampleIntervalSeconds 1

- So sánh với trạng thái PythonAgent idle để đánh giá phần AMSI bridge.

Bước 5: Đo workload bình thường

Mục tiêu: đánh giá tác động khi người dùng thao tác bình thường.

Checkpoint sử dụng:
- CP03_PythonAgent_CPPAgent_OK nếu muốn đo cả PythonAgent và C++ Agent.
- CP02_PythonAgent_Health_OK nếu chỉ muốn đo PythonAgent.

Có thể thực hiện:
- Mở PowerShell và chạy một số lệnh lành tính.
- Tạo/sửa/xóa một vài file .ps1 trong thư mục watch path.
- Mở trình duyệt hoặc thao tác Windows cơ bản nếu cần.

Khuyến nghị:
- Nên dùng script mô phỏng workload bình thường để các lần đo có cùng thao tác.
- Script workload tạo file .ps1/.txt lành tính trong Documents, đọc/sửa file và chạy một số lệnh PowerShell quản trị thông thường.
- Không dùng thao tác tay làm số liệu chính nếu muốn so sánh trung bình giữa các lần đo.

Script đo workload bình thường:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_normal_workload.ps1 -Label normal_workload_run1 -DurationSeconds 120 -SampleIntervalSeconds 1

Lệnh trên sẽ:
- Chạy run_normal_workload.ps1 ở background.
- Đồng thời chạy measure_performance.ps1 để đo CPU/RAM/IO.
- In ra Summary để ghi số liệu.

Quy trình đo:
- Restore về checkpoint đã chọn.
- Đợi 1 đến 2 phút.
- Chạy measure_normal_workload.ps1.
- Khi script kết thúc, ghi số liệu Summary ra giấy.
- Ghi thêm nhận xét có bị chậm, giật hoặc delay rõ rệt hay không.

Đo lặp lại:
- Run1 xong thì ghi số liệu.
- Đợi 60 giây.
- Chạy run2:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_normal_workload.ps1 -Label normal_workload_run2 -DurationSeconds 120 -SampleIntervalSeconds 1

- Đợi 60 giây.
- Chạy run3:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_normal_workload.ps1 -Label normal_workload_run3 -DurationSeconds 120 -SampleIntervalSeconds 1

- Nếu muốn dùng quy ước warm-up giống baseline, chạy thêm run4:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_normal_workload.ps1 -Label normal_workload_run4 -DurationSeconds 120 -SampleIntervalSeconds 1

Lưu ý:
- Workload phải giống nhau giữa các lần đo. Dùng script giúp đảm bảo điều này.
- Nếu thao tác tạo nhiều file/log, nên restore lại checkpoint trước mỗi lần đo để tránh log cũ ảnh hưởng IO.
- Nếu muốn dọn file workload sau mỗi lần chạy, thêm tham số -CleanupAfterRun.
- Nếu muốn lưu CSV, thêm tham số -OutputCsvPath .\perf_results.csv.
- Ghi thêm nhận xét cảm nhận: có bị chậm, treo, delay cửa sổ hay không.

Bước 6: Đo workload mô phỏng tấn công

Mục tiêu: đánh giá tác động khi agent xử lý telemetry đáng nghi.

Checkpoint sử dụng:
- CP03_PythonAgent_CPPAgent_OK nếu test có AMSI bridge.
- CP02_PythonAgent_Health_OK nếu chỉ test sensor PythonAgent.

Có thể dùng:
- Synthetic attack workload: script mô phỏng PowerShell đáng nghi nhưng không phá hệ thống.
- Atomic Red Team test đã chuẩn bị.
- Case Event Log 4104 nếu đã bật Script Block Logging.

Khuyến nghị:
- Dùng Synthetic attack workload làm số liệu định lượng chính nếu muốn workload ngắn, ổn định và ít phụ thuộc môi trường.
- Dùng Mode Both nếu muốn đo đồng thời synthetic workload và Atomic Red Team selected tests.
- Atomic Red Team phụ thuộc bộ Atomic, prereq, thời gian chạy từng test và môi trường C:\AtomicRedTeam.
- Response nên để tắt ở bước này. Response được đo riêng ở Bước 7.

Synthetic attack workload thực hiện các hành vi đáng nghi nhưng vô hại:
- Chạy PowerShell với -EncodedCommand chứa lệnh benign.
- Giải mã chuỗi bằng FromBase64String nhưng không tải hoặc thực thi mã độc.
- Dùng Invoke-Expression với chuỗi Write-Output benign.
- Chạy PowerShell hidden window với lệnh benign.
- Tạo và chạy file .ps1 chứa indicator đáng nghi để kích hoạt file sensor/eventlog sensor.

Quy trình đo:
- Restore về checkpoint đã chọn trước mỗi lần đo để kết quả sạch hơn.
- Đợi 1 đến 2 phút.
- Chạy script đo attack workload.
- Sau khi script đo xong, ghi số liệu ra giấy.
- Ghi thêm số event mới sinh ra trong edr_events.jsonl.
- Ghi verdict chính: ALLOW, ALERT hoặc TERMINATE.

Lệnh đo synthetic attack workload:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Synthetic -Label attack_synthetic_run1 -DurationSeconds 120 -SampleIntervalSeconds 1

Lệnh đo kết hợp Synthetic + Atomic Red Team:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run1 -DurationSeconds 600 -SampleIntervalSeconds 1

Điều kiện để dùng Mode Both:
- Máy test đã cài Atomic Red Team vào C:\AtomicRedTeam.
- Runtime package có tests\atomic_red_team\run_selected_atomic_tests.ps1.
- Runtime package có tests\atomic_red_team\selected_atomic_tests.json.
- PythonAgent đang chạy và health OK.
- Nếu cần AMSI bridge, AgentConsole.exe cũng đang chạy.

Đo lặp lại:
- Với workload tấn công, nên restore về checkpoint trước mỗi run.
- Với Mode Synthetic, chạy run1 đến run4:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Synthetic -Label attack_synthetic_run1 -DurationSeconds 120 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Synthetic -Label attack_synthetic_run2 -DurationSeconds 120 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Synthetic -Label attack_synthetic_run3 -DurationSeconds 120 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Synthetic -Label attack_synthetic_run4 -DurationSeconds 120 -SampleIntervalSeconds 1

- Với Mode Both, chạy run1 đến run4:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run1 -DurationSeconds 600 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run2 -DurationSeconds 600 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run3 -DurationSeconds 600 -SampleIntervalSeconds 1
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Both -Label attack_both_run4 -DurationSeconds 600 -SampleIntervalSeconds 1

- Có thể xem run1 là warm-up và lấy trung bình run2-run4 nếu run1 lệch nhiều.

Nếu muốn dọn file workload sau mỗi lần chạy:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Synthetic -Label attack_synthetic_run1 -DurationSeconds 120 -SampleIntervalSeconds 1 -CleanupAfterRun

Nếu muốn đo bằng Atomic Red Team:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_attack_workload.ps1 -Mode Atomic -Label attack_atomic_run1 -DurationSeconds 600 -SampleIntervalSeconds 1 -AtomicRunnerPath .\tests\atomic_red_team\run_selected_atomic_tests.ps1 -SelectedTestsPath .\tests\atomic_red_team\selected_atomic_tests.json

Điều kiện để dùng Mode Atomic:
- Gói runtime phải có thêm thư mục tests\atomic_red_team.
- Máy test đã cài Invoke-AtomicRedTeam và atomics, ví dụ C:\AtomicRedTeam.
- PythonAgent đang chạy và health OK.
- Nên dùng cùng selected_atomic_tests.json giữa các lần đo.

Lưu ý:
- Không so sánh run nếu mỗi lần chạy một payload hoặc danh sách Atomic khác nhau.
- Nếu log quá lớn, copy log cần giữ ra ngoài VM rồi dọn log trước khi tạo checkpoint mới.
- Detection latency chỉ nên ghi nếu có mốc thời gian bắt đầu test và mốc event xuất hiện trong log.
- Nếu bật Event Log 4104, synthetic attack workload sẽ sinh thêm telemetry 4104. Đây là hành vi mong muốn trong bài đo.

Hướng dẫn cài Atomic Red Team trên máy test nằm tại:

docs\atomic_red_team_install_on_test_vm_vi.md

Bước 7: Đo response

Checkpoint sử dụng:
- CP04_Before_Response_Test

- Restore về CP04 trước mỗi lần đo response.
- Bật response:

$env:EDR_ENABLE_RESPONSE = "1"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\start_python_agent.ps1 -Force

- Đợi 1 đến 2 phút cho agent ổn định.
- Bắt đầu script đo:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label response_run1 -DurationSeconds 120 -SampleIntervalSeconds 1

- Trong lúc script đo đang chạy, chạy case có final_verdict = TERMINATE.
- Kiểm tra:

PythonAgent\logs\response_actions.jsonl
PythonAgent\quarantine

Thu thập:
- Response có được thực hiện hay không.
- Thời gian từ khi phát hiện đến khi có log response.
- File có bị quarantine đúng điều kiện hay không.
- Có tránh protected list hay không.

Đo lặp lại:
- Response có thể thay đổi trạng thái file/process, vì vậy nên restore CP04 trước mỗi run.
- Chạy response_run1, response_run2, response_run3.
- Dùng cùng một case TERMINATE để kết quả có thể so sánh.

Bước 8: Lặp lại và lấy trung bình

Nên đo mỗi trạng thái ít nhất 3 lần:
- Lần 1: số liệu chính hoặc đo thử nếu lần đầu thao tác chưa quen.
- Lần 2 và 3: số liệu chính để lấy trung bình.

Cách lấy trung bình thủ công:
- Với mỗi chỉ số, cộng 3 lần đo rồi chia cho 3.
- Ví dụ CPU PythonAgent trung bình = (run1 + run2 + run3) / 3.
- Nếu một run có số liệu bất thường do Windows Update, lag VM hoặc thao tác sai, ghi chú lại và đo lại run đó.

Nếu thời gian hạn chế, tối thiểu nên đo:
- Baseline.
- PythonAgent idle.
- PythonAgent + C++ Agent idle.
- Atomic/workload tấn công.
- Response enabled.

12.4. Lệnh đo nhanh bằng PowerShell

Script đo khuyến nghị:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label test_run1 -DurationSeconds 60 -SampleIntervalSeconds 1

Script này sẽ in ra phần Summary gồm CPU/RAM/IO trung bình. Có thể ghi số liệu ra giấy trực tiếp từ màn hình.

Nếu muốn lưu CSV để kiểm tra lại sau:

powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\measure_performance.ps1 -Label test_run1 -DurationSeconds 60 -SampleIntervalSeconds 1 -OutputCsvPath .\perf_results.csv

Kiểm tra tiến trình:

Get-Process python, AgentConsole -ErrorAction SilentlyContinue |
Select-Object ProcessName, Id, CPU, WorkingSet64, PrivateMemorySize64, StartTime

Đo counter trong 60 giây:

Get-Counter `
  '\Processor(_Total)\% Processor Time',
  '\Memory\Available MBytes',
  '\Process(python*)\% Processor Time',
  '\Process(python*)\Working Set - Private',
  '\Process(python*)\IO Read Bytes/sec',
  '\Process(python*)\IO Write Bytes/sec' `
  -SampleInterval 1 -MaxSamples 60

Nếu cần lưu ra file, có thể ghi transcript:

Start-Transcript .\perf_measure_result.txt

Sau khi đo xong:

Stop-Transcript

12.4.1. Lưu ý để số liệu chính xác hơn

- Không đo ngay sau khi boot hoặc restore checkpoint. Nên đợi 3 đến 5 phút.
- Sau khi start PythonAgent hoặc AgentConsole, nên đợi 1 đến 2 phút rồi mới đo.
- Không mở thêm ứng dụng trong lúc đang đo.
- Không kéo thả cửa sổ, copy file lớn, cập nhật Windows hoặc cài phần mềm trong lúc đo.
- Dùng cùng DurationSeconds và SampleIntervalSeconds cho các trạng thái cần so sánh.
- Với workload tấn công hoặc response, nên restore checkpoint trước mỗi lần đo.
- Với idle/baseline, có thể đo 3 lần liên tiếp, mỗi lần cách nhau khoảng 60 giây.
- Ghi lại cả cấu hình VM: số core, RAM, loại ổ đĩa ảo, dung lượng còn trống.
- Nếu host đang tải nặng, nên dừng đo và đo lại sau vì VM sẽ bị ảnh hưởng.
- Nếu số liệu run nào quá lệch so với hai run còn lại, ghi chú nguyên nhân hoặc đo lại run đó.

12.5. Bảng kết quả nên dùng trong báo cáo

Nên tổng hợp theo bảng:

Trạng thái đo | CPU trung bình | RAM trung bình | Disk IO | Số event | Nhận xét

Các trạng thái khuyến nghị:
- Baseline - agent chưa chạy.
- PythonAgent idle.
- PythonAgent + C++ Agent idle.
- Workload bình thường.
- Atomic/workload tấn công.
- Response enabled.

13. Lỗi thường gặp

Lỗi: python không được nhận diện.
Cách xử lý: cài Python 3.10+ và thêm Python vào PATH.

Lỗi: pip install thất bại.
Cách xử lý: kiểm tra Internet, proxy, hoặc chạy lại lệnh setup bằng PowerShell Administrator nếu môi trường hạn chế quyền.

Lỗi: đăng ký AmsiProvider.dll thất bại.
Cách xử lý: mở PowerShell bằng quyền Administrator và kiểm tra đã cài Visual C++ Redistributable x64.

Lỗi: eventlog_4104_sensor = false.
Cách xử lý: kiểm tra pywin32 đã cài, bật Script Block Logging và chạy lại PythonAgent.

Lỗi: response không hoạt động.
Cách xử lý: kiểm tra đã đặt EDR_ENABLE_RESPONSE=1 trước khi start PythonAgent, kiểm tra final_verdict có phải TERMINATE hay không, và kiểm tra response_actions.jsonl.
