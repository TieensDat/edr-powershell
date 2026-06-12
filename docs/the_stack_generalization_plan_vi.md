# Ke hoach kiem tra generalization voi The Stack

Muc tieu cua buoc nay la dung The Stack nhu mot tap du lieu ngoai mien de kiem tra kha nang tong quat hoa cua PythonAgent sau khi da tuning tren PowerShell Gallery va Chocolatey. The Stack khong duoc dung lam nguon tuning chinh ngay tu dau, ma duoc dung nhu holdout de kiem tra xem rule hien tai co bi overfit vao hai tap benign truoc do hay khong.

## 1. Trang thai freeze truoc khi chay

Truoc khi thu thap va danh gia The Stack, can dong bang trang thai hien tai cua agent.

Can ghi lai:

- Git commit hien tai.
- Ngay gio freeze.
- File agent: `PythonAgent/PythonAgent.py`.
- Trang thai model ML: model path, feature columns, ML enabled hay disabled.
- Cac vong tuning da hoan thanh:
  - Atomic Red Team expanded.
  - PowerShell Gallery behavior groups.
  - Chocolatey behavior groups.

Muc dich:

- Bao dam ket qua The Stack phan anh dung mot phien ban agent cu the.
- Neu sau nay tuning tiep, co the so sanh truoc/sau mot cach ro rang.

## 2. Thu thap pilot The Stack

Pilot la buoc nho de kiem tra pipeline truoc khi lay tap lon.

Cau hinh de xuat:

| Tham so | Gia tri |
|---|---:|
| Tong file pilot | 100-200 |
| Ngon ngu | PowerShell |
| Extension | `.ps1`, `.psm1`, `.psd1` |
| Max file size | 200 KB |
| Min file size | 200 bytes |
| Max file/repository | 5 |
| Thuc thi script | Khong |

Can luu:

```text
datasets/the_stack/powershell_pilot/metadata/files_manifest.csv
datasets/the_stack/powershell_pilot/metadata/skipped_manifest.csv
datasets/the_stack/powershell_pilot/metadata/collection_summary.json
```

Metadata can co:

- `sample_id`
- `source_dataset`
- `dataset_version`
- `repo_name`
- `repo_path`
- `license`
- `extension`
- `file_size_bytes`
- `raw_sha256`
- `normalized_sha256`
- `collection_time`

## 3. Dedup voi dataset cu

Truoc khi danh gia, can loai trung voi cac nguon da dung truoc do.

Nguon can dedup:

- Dataset TLCN cu:
  - Malicious PowerShell Dataset.
  - Benign PowerShell Dataset.
- PowerShell Gallery behavior groups.
- Chocolatey behavior groups.
- The Stack pilot neu chay lai nhieu lan.

Can dedup bang:

- `raw_sha256`: trung noi dung goc.
- `normalized_sha256`: trung sau khi normalize whitespace/lowercase.

Ket qua can luu:

```text
datasets/the_stack/powershell_holdout/metadata/dedup_summary.json
datasets/the_stack/powershell_holdout/metadata/duplicate_manifest.csv
```

Muc dich:

- Bao dam The Stack la tap ngoai mien tuong doi doc lap.
- Giam nguy co bao cao ket qua bi lap voi cac tap tuning truoc.

## 4. Thu thap holdout chinh

Sau khi pilot on dinh, thu thap tap holdout chinh.

Cau hinh de xuat:

| Loai file | So luong muc tieu |
|---|---:|
| `.ps1` | 600 |
| `.psm1` | 250 |
| `.psd1` | 150 |
| Tong | 1000 |

Neu may test yeu hoac download cham, co the bat dau voi 500 file:

| Loai file | So luong muc tieu |
|---|---:|
| `.ps1` | 300 |
| `.psm1` | 125 |
| `.psd1` | 75 |
| Tong | 500 |

Luu y:

- Khong thuc thi script tu The Stack.
- Khong dung The Stack holdout de tuning truc tiep.
- Neu can tuning bang The Stack, phai tach rieng mot tap `stack_tuning_candidate`.

## 5. Chay static baseline

Quy trinh danh gia:

1. Doc tung file trong manifest.
2. Goi logic `build_detection_result()` cua PythonAgent.
3. Ghi lai:
   - `final_verdict`
   - `rule_verdict`
   - `ml_verdict`
   - `ml_confidence`
   - `risk_level`
   - `risk_score`
   - `raw_risk_score`
   - `benign_score`
   - `reasons`
4. Khong dua vao queue response.
5. Khong quarantine.
6. Khong kill process.

Output can co:

```text
datasets/the_stack/powershell_holdout/reports/evaluation_results.csv
datasets/the_stack/powershell_holdout/reports/alert_or_terminate_results.csv
datasets/the_stack/powershell_holdout/reports/summary_by_extension.csv
datasets/the_stack/powershell_holdout/reports/summary_by_size_bucket.csv
datasets/the_stack/powershell_holdout/reports/top_alert_reasons.csv
```

## 6. Review ALERT va TERMINATE

Can review thu cong:

- 100% mau `TERMINATE`.
- 100% mau `HIGH ALERT`.
- Toi thieu 30-50 mau `ALERT` con lai.
- Random 30 mau `ALLOW` de sanity check.

Phan loai review:

| Nhan | Y nghia |
|---|---|
| `acceptable_alert` | Canh bao hop ly vi script co behavior admin/security/installer dual-use. |
| `true_fp_candidate` | Ung vien false positive, pattern benign ro rang. |
| `suspicious_public_code` | Code public co hanh vi dang nghi that su, khong nen coi la FP. |
| `unknown_needs_context` | Can them context repository hoac runtime moi ket luan. |

Manual review can luu:

```text
datasets/the_stack/powershell_holdout/reports/manual_review.csv
```

Cot de xuat:

- `sample_id`
- `repo_name`
- `repo_path`
- `extension`
- `final_verdict`
- `risk_level`
- `reasons`
- `manual_label`
- `review_note`
- `reviewer`
- `review_time`

## 7. Viet bao cao generalization

Bao cao nen luu tai:

```text
docs/the_stack_generalization_report_vi.md
```

Noi dung bao cao:

1. Muc tieu.
2. Ly do dung The Stack lam tap ngoai mien.
3. Cach thu thap du lieu.
4. Tieu chi loc va dedup.
5. Quy trinh chay static baseline.
6. Ket qua tong hop.
7. Phan tich `ALERT`/`TERMINATE`.
8. Manual review.
9. Nhan xet ve kha nang tong quat hoa.
10. Han che.
11. Ket luan co can tuning tiep hay khong.

Khong nen viet:

- "The Stack la tap benign 100%".
- "Alert rate bang false positive rate".

Nen viet:

- "The Stack la tap ma nguon public ngoai mien".
- "`ALERT` tren The Stack la ung vien can review, khong mac dinh la FP".
- "`TERMINATE` tren code public can duoc review ky vi co nguy co over-response".

## 8. Dieu kien tuning tiep

Chi tuning tiep neu co pattern lap lai ro rang, vi du:

- Nhieu alert chi do URL trong comment/documentation.
- Nhieu alert chi do checksum/manifest/static metadata.
- Nhieu alert chi do file `.psd1` module manifest.
- Nhieu alert do test fixture benign, khong co execution chain.

Khong tuning neu:

- Chi co mot vai mau le.
- Script co dynamic execution, download-execute, registry persistence, service/task, credential, AMSI bypass, Defender tampering.
- Mau co hanh vi admin/security dual-use nhung chua co context ro.

Sau moi tuning:

1. Chay lai The Stack pilot/holdout.
2. Chay lai PowerShell Gallery holdout.
3. Chay lai Chocolatey baseline.
4. Chay lai Atomic expanded.
5. Ghi ket qua truoc/sau vao report.

## 9. Ket luan quy trinh

Pipeline chuan:

```text
Freeze agent hien tai
-> Thu thap pilot The Stack
-> Dedup voi dataset cu
-> Chay static baseline
-> Review ALERT/TERMINATE
-> Viet bao cao generalization
-> Chi tuning tiep neu co pattern lap lai ro rang
```

Buoc nay giup chung minh he thong khong chi duoc tuning tren PowerShell Gallery va Chocolatey, ma con duoc kiem tra tren tap ma PowerShell public ngoai mien.
