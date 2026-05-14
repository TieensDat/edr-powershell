# Checklist hoan thanh de tai khoa luan

Checklist nay dung de theo doi cac viec con lai truoc khi nop bao cao va demo de tai Mini EDR PowerShell.

## 1. Don repo

- [x] Kiem tra `git status` de biet file nao dang thay doi.
- [x] Dam bao `.gitignore` da bo qua file runtime: `.exe`, `.dll`, `logs`, `quarantine`, `.env`, cache.
- [x] Khong commit file trong `PythonAgent/quarantine/`.
- [x] Khong commit log runtime lon trong `PythonAgent/logs/`.
- [x] Quyet dinh co dua model `.pkl` len repo hay khong. Hien tai model duoc giu local va bi ignore boi `.gitignore`.
- [x] Giu lai cac report JSON/Markdown can lam bang chung trong `tests/` va `docs/`.
- [ ] Tao commit sach cho phan code, test va tai lieu.

Trang thai sau khi don:

- `PythonAgent/logs/` chi con `.gitkeep`.
- `PythonAgent/quarantine/` chi con `.gitkeep`.
- Da xoa cache Python va cac thu muc runtime test.
- `bin/AgentConsole.exe` va `bin/AmsiProvider.dll` duoc giu local de demo, nhung khong bi commit do `.gitignore`.

## 2. Tao tai lieu demo end-to-end

- [ ] Viet thu tu chay demo: PythonAgent -> AgentConsole -> PowerShell payload.
- [ ] Ghi ro cach bat response: `EDR_ENABLE_RESPONSE=1`.
- [ ] Ghi ro cach kiem tra AMSI Provider da dang ky.
- [ ] Ghi ro payload demo an toan trong lab.
- [ ] Ghi ro dau hieu thanh cong: event `amsi_cpp_bridge`, verdict `TERMINATE`, C++ Agent terminate process.
- [ ] Dua duong dan report demo: `tests/amsi_bridge/registered_amsi_provider_report.json`.

## 3. Chot bang ket qua thuc nghiem

- [ ] Dua bang tong hop tu `docs/experiment_results_summary.md` vao bao cao.
- [ ] Trinh bay ket qua File Sensor: `20/20`.
- [ ] Trinh bay ket qua Process Sensor: `20/20`.
- [ ] Trinh bay ket qua Event Log 4104 Sensor: `20/20`.
- [ ] Trinh bay ket qua ML runtime.
- [ ] Trinh bay ket qua Atomic Red Team: `12/12` co telemetry.
- [ ] Trinh bay ket qua Response Engine: `15/15`.
- [ ] Trinh bay ket qua AMSI Provider E2E: pass.

## 4. Chup hinh minh chung

- [ ] Hinh health endpoint cua PythonAgent.
- [ ] Hinh report File/Process/Event Sensor.
- [ ] Hinh report Atomic Red Team.
- [ ] Hinh report Response Engine.
- [ ] Hinh report Registered AMSI Provider E2E.
- [ ] Hinh `edr_cpp_agent.log` co cac dong `[AMSI]`, `[FORWARD]`, `[PYTHON_AGENT]`, `[ACTION]`.
- [ ] Hinh mot event trong `edr_events.jsonl` co `source`, `rule_verdict`, `ml_verdict`, `final_verdict`, `response_action`.

## 5. Hoan thien noi dung bao cao

- [ ] Chuong tong quan: ly do chon de tai, PowerShell abuse, EDR, AMSI, Event Log 4104.
- [ ] Chuong co so ly thuyet: PowerShell attack, telemetry, feature extraction, rule detection, ML, response.
- [ ] Chuong thiet ke he thong: kien truc C++ + PythonAgent.
- [ ] Chuong trien khai: mo ta AMSI Provider, AgentConsole, PythonAgent, sensors, ML, response.
- [ ] Chuong thuc nghiem: moi truong, kich ban test, ket qua, bang va hinh.
- [ ] Chuong danh gia: diem dat duoc, gioi han, huong phat trien.
- [ ] Dua phan gioi han tu `docs/system_limitations.md` vao bao cao.

## 6. Kiem tra lai truoc khi nop

- [ ] Chay lai response test neu co sua code PythonAgent.
- [ ] Chay lai AMSI Provider E2E test de dam bao demo con hoat dong.
- [ ] Kiem tra `README.md` co huong dan chay co ban.
- [ ] Kiem tra cac duong dan trong tai lieu khong bi sai.
- [ ] Kiem tra khong con thong tin nhay cam nhu API key, token, file ca nhan.
- [ ] Kiem tra repo push len GitHub dung remote.

## 7. Chuan bi phan bao ve

- [ ] Chuan bi kich ban demo ngan 3-5 phut.
- [ ] Chuan bi cau tra loi: vi sao dung AMSI, vi sao dung Event ID 4104, vi sao Event Log khong kill truc tiep.
- [ ] Chuan bi cau tra loi ve ML: model dung de ho tro phan loai, rule baseline van hoat dong khi ML loi.
- [ ] Chuan bi cau tra loi ve response: proof-of-concept, chua production-grade.
- [ ] Chuan bi cau tra loi ve gioi han va huong phat trien.

## 8. Viec khong nen lam them luc nay

- [ ] Khong mo rong them tinh nang lon neu khong bat buoc.
- [ ] Khong thay doi detection rule lon truoc khi nop neu khong co thoi gian test lai.
- [ ] Khong them dashboard phuc tap neu bao cao va demo chua xong.
- [ ] Khong toi uu ML qua sau neu chua co dataset va thoi gian danh gia day du.

## Ket luan

Project hien tai da dat muc ky thuat can thiet cho khoa luan. Phan viec con lai chu yeu la dong goi, tai lieu hoa, chuan bi bang chung, chuan bi demo va viet bao cao mot cach ro rang.
