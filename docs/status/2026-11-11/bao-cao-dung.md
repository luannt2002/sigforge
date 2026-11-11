# sigforge — báo cáo dừng đợt v0.5 · 11/11/2026

Chủ dự án bảo "tạm stop không làm nữa, viết hết report + commit + push" (11/11). Đây là chỗ đọc DUY NHẤT để biết đã làm gì,
còn gì, và làm tiếp thế nào. Chi tiết từng lượt nằm ở sổ `sigforge-tien-do-2026-11-10.md`.

## 1. Tóm tắt
- **v0.5.0 CHƯA phát hành.** Mục RC chưa đạt: đợt 2 còn 3 task chưa gộp, đợt 3 chưa làm, chưa có A-RC. Không tag, không bump version.
- **Đã push lên `main`:** baseline v0.5 (17 commit theo nhóm) + 10 task đã gộp (mỗi task 1 commit). Chi tiết ở mục 2 và 6.
- **Chưa gộp nhưng ĐÃ PUSH thành nhánh riêng** (lệnh 11/11 "đưa hết lên, chưa xong cũng được"): `wip/g01`, `wip/g10b`, `wip/g05b` — mỗi
  nhánh = `main` + 1 commit ghi rõ "NOT REVIEWED". Cả ba đã qua trọng tài (J); lượt soát độc lập bị cắt. `main` vẫn chỉ có phần đã soát.
- **Báo cáo trạng thái public:** nhánh `wip/v0.5-status` (`docs/v0.5-status.md`, tiếng Anh, đã lọc đường dẫn máy / tên nội bộ).
- **Lý do dừng giữa chừng:** mọi subagent bị cắt lúc ~17:5x 10/11 vì hết hạn mức tuần (reset 13/11 01:00, giờ VN).

## 2. Đã làm, theo gói — mức bằng chứng
"ĐÃ CHẠY" = điều phối hoặc người soát tự chạy lệnh; "agent khai" = chỉ có lời worker.

| Gói | Trạng thái | Bằng chứng |
|---|---|---|
| Baseline v0.5 (T0a/T0b, 53 tệp) | đã push, 17 commit | T0a soát ĐẠT sau W1; cổng mỗi commit: build + vet; test toàn cây ở cuối nhóm 17 (ĐÃ CHẠY) |
| W1 watch không "yên" khi không tra gì | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| W2 cờ inventory rỗng | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| G04 cổng refresh | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| G06 WordPress core trong feedset | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| G02 OSV `limit` | đã push | R DAT · gộp + cổng (ĐÃ CHẠY); `indexFormat /11` đi CÙNG B2 |
| G08 release dưới floor giữ lead | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| B9 `--package` tên trắng | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| B2 floor tất định | đã push | R DAT · gộp + cổng (ĐÃ CHẠY) |
| B10 test `limit` 12 họ comparator | đã push | J + R DAT; gộp 16:38, 616 pass, mất 0 (ĐÃ CHẠY) |
| W3 sync giữ bản tốt khi nguồn trả rác | đã push | Code: R lượt 2 + R-Δ 4/5/6 xác nhận đúng. Test: KHONG-DAT 3 lần cùng lớp ⇒ gộp theo ngưỡng chủ dự án, giới hạn **F55**. Gộp 17:11, 648 pass, mất 0 (ĐÃ CHẠY) |
| G01 `requires`/`excludes` + LC-2 + hiệu năng | đã push nhánh `wip/g01` (`0ac5b47` = main + bản r9; cổng nhánh: build + vet, 743 pass / 0 fail), CHƯA gộp | J ĐẠT đủ (r8/r9: sha, đo xen kẽ Shopify 226 µs / trang dị thường 5,57 ms, test chặn đỏ trên r7, 621 pass, Q1 115 ⇒ 2 sống tương đương) (ĐÃ CHẠY). R lượt 9: bị cắt, chưa có kết luận |
| G05b `watch` theo bảng G05a | đã push nhánh `wip/g05b` (`18e3c89` = main + bản r5; xung đột dòng kề `CODE-MAP.md` với W3 giải bằng máy, có kiểm mỗi bên chỉ đổi dòng của mình; cổng nhánh: 766 pass / 0 fail), CHƯA gộp | J ĐẠT (r5: test mô hình 500 lượt; 5 đột biến J tự viết đều đỏ chỉ với test mô hình; 702 pass) (ĐÃ CHẠY). R-Δ lượt 5 bị cắt; kết quả tạm của người soát: 10 đột biến R-Δ4 ⇒ 9 ĐỎ + C10-swap sống (đúng dự kiến) — agent khai, chưa hoàn tất |
| G10b matcher `dom` thụ động | đã push nhánh `wip/g10b` (`06dabd2` = main + bản r4; cổng nhánh: 819 pass / 0 fail), CHƯA gộp | J ĐẠT đủ (r4: repro đỏ trên r3 tái tạo, xanh r4; 714 pass; Q1 268 ⇒ 11 sống = 11 tương đương cũ) (ĐÃ CHẠY). Số đo dữ liệu thật (golden TP 42/42, FP 190 → 8): agent khai ở r4, J đã chạy ở r2. R lượt 2: bị cắt |
| W3b đường chạy không ghi rác vào kho | CHƯA làm | Brief `briefs/W3b-luot1.md` đã qua cổng; worker bị cắt trước khi sửa tệp nào |
| S1 đo sync thật, G03k, G05a, G01a, G10a | xong (đo / soát, không code) | báo cáo riêng trong `notes/sigforge/` |

## 3. Cổng đã chặn được trong đợt (bằng chứng cổng có tác dụng)
- **G01 lượt 7:** đúng nghĩa nhưng chậm ×81–×108 (trang dị thường 46 ms → 4,98 s — DoS trên trang ngoài) ⇒ lượt 8 về 5,6 ms.
- **G10b lượt 3:** worker tự tìm ra `</scripts>` kết thúc script sớm ⇒ thẻ giả bắn luật ⇒ lượt 4 sửa theo luật HTML.
- **G05b lượt 4:** 10 đột biến "lẫn giữa danh tính" sống qua 698 test (vd GONE oan khi một nguồn sập) ⇒ chủ dự án chọn đổi khuôn ⇒ test
  mô hình bắt cả lớp.
- **W3 lượt 4–6:** lần lượt A3/H1/H2 → E8–E11 → N4… (test lý do lỗi chưa đủ chặt) ⇒ dừng theo ngưỡng, ghi F55.
- **Điều phối tự sai 2 lần, cổng bắt:** so tên test sai định dạng (báo "mất 591" oan) — sửa lệnh so trước khi kết luận.

## 4. Còn làm, theo thứ tự (từ 13/11, khi hạn mức reset)
1. Dựng lại worktree từ nhánh tạm nếu `/tmp` đã mất (lệnh ở mục 7), rồi giao lại 3 lượt soát bằng đúng brief cũ:
   `briefs/G01-R-luot9.md`, `briefs/G05b-RD-luot5.md`, `briefs/G10b-R-luot4.md`.
2. Gộp theo luật M khi DAT, thứ tự đề xuất: G01 → G10b → G05b.
   - G05b phải dựng lại `docs/CODE-MAP.md` trên bản W3 đã gộp (xung đột dòng kề, đã đo) — một lượt chỉ tài liệu + R-Δ.
   - Giả lập đã đo: G01 × G10b gộp sạch ở `matcher.go` / `schema.go` / `matcher.md`; G01 `enrich-pipeline.md` đã dựng lại trên G08.
3. Đợt 3 theo làn: W3b → B1 · B11 → B5 · B4 (sau G05b, B11) · B3 (sau W3b) · B8 cuối.
4. A-RC (audit chỉ đọc) → CHANGELOG (kèm "giới hạn đã biết") → tag `v0.5.0` + push (phép đã có cho riêng v0.5.0, khi A-RC DAT).

## 5. Câu cần chủ dự án quyết
1. Mục README "sigforge làm được gì" (lõi RC AC7): điều phối đang GIỮ, vì chỉ phần "viết lại luồng" bị bỏ (10/11). Giữ hay bỏ?
2. F55 (lỗ test W3: lỗi nhiều dòng chưa bị chặn): sửa trong v0.5.0 (vài dòng test, đã có hướng sửa) hay để bản sau?
3. F56 (matcher `dom` vẫn đọc thẻ trong `<textarea>` / `<title>`): làm trong v0.5.0 hay để sau? Mới nghi, chưa đo.

## 6. Code đang nằm ở đâu
| Nơi | Nội dung |
|---|---|
| `origin/main` (GitHub, public) | `57c893f` — baseline v0.5 + 10 task, 27 commit trên `632342f` (v0.4.0). Push 11/11: `632342f..57c893f`. Kiểm trước push: cây commit cuối trùng cây đã test (`a6059b21…`); mỗi commit build + vet, mỗi commit task test toàn cây; quét 5.685 dòng thêm: 0 khoá, 0 IP riêng / tên nội bộ, 0 tệp lớn / binary |
| `origin/wip/g01` `0ac5b47` · `origin/wip/g10b` `06dabd2` · `origin/wip/g05b` `18e3c89` | main + bản vá chưa soát, mỗi nhánh 1 commit — ĐÃ push 11/11, KHÔNG merge khi chưa có R DAT |
| `origin/wip/v0.5-status` `966f546` | main + `docs/v0.5-status.md` (báo cáo public) — ĐÃ push 11/11 |
| nhánh local `wip/g01-r9` / `wip/g05b-r5` / `wip/g10b-r4` | ảnh chụp worktree gốc từng task (HEAD `632342f` + phần chưa commit lúc đó) — local, không push |
| nhánh local `v05-checkpoint` | trùng `main` sau khi push (dùng để dựng chuỗi commit) |
| `notes/sigforge/luu-tru-2026-11-11/` | bản vá + sha (`ban-va/SHA256SUMS`), báo cáo soát (`soat/`), base gộp 3 chiều (`base/base-dot1`, `base/wt-g04`, `base/g01-base-r9`), sao lưu gộp (`base/merge-backup`) |
| `<scratch>/` | worktree + bằng chứng đầy đủ; có thể mất khi khởi động lại máy |

## 7. Lệnh làm tiếp
```bash
cd <repo>
git worktree add <scratch> wip/g01-r9     # tương tự wt-g05b, wt-g10b
# bản vá gốc để chấm / gộp: notes/sigforge/luu-tru-2026-11-11/ban-va/ (kiểm bằng sha256sum -c SHA256SUMS)
# mọi lệnh Go: <notes>/cong-cu/goslot go …
# brief mới: python3 -I <notes>/cong-cu/kiem_brief.py <brief>  (rc=0 mới giao)
```
Lưu ý:
- Nhánh ĐÃ PUSH `wip/g01`, `wip/g10b`, `wip/g05b` = `main` + 1 commit. Khi R DAT trên đúng bản đó, gộp được bằng fast-forward / cherry-pick.
  Phải kiểm sha nội dung khớp bản vá đã soát.
- Nhánh LOCAL `wip/*-rN` là ảnh chụp worktree gốc (chứa cả phần baseline cũ) ⇒ chỉ dùng để dựng lại worktree soát, KHÔNG merge.
- Worktree cho người soát: `git worktree add <thư mục> wip/g01-r9` (giữ đúng base của bản vá đã nộp).

## 8. Log (trong `luu-tru-2026-11-11/`)
- `dung_commit.py` + `dung.log`: dựng 27 commit của `main` (kiểm backup trước-gộp từng task, cổng từng commit).
- `ap_wip.py`: áp bản vá chưa soát lên `main` theo base của task (gộp 3 chiều, in xung đột).
- `log/wip-{g01,g10b,g05b}-go-test.json`: `go test -json ./...` của từng nhánh WIP.
- `log/agent-bi-cat-ket-qua-do.txt`: toàn bộ lời các agent soát / worker bị cắt đã kịp viết (kết quả dở).
  - R-Δ G05b lượt 5: 10 đột biến R-Δ4 ⇒ 9 ĐỎ + C10-swap sống (đúng dự kiến); đang chạy 12 đột biến riêng thì bị cắt.
  - R G01 lượt 9: xác nhận `matcher.go` r7 do J tái tạo là đúng; đang chạy probe thì bị cắt — chưa có kết luận.
  - R G10b lượt 2: mới đọc công cụ đo; W3b: chưa làm gì.
- `soat/`: báo cáo soát và output Q1 / đột biến của J; `ban-va/`: bản vá + `SHA256SUMS`.
