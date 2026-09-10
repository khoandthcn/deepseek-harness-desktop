# DeepSeek Harness Desktop — bản build không ký cho Windows 11 & macOS

Đóng gói **ứng dụng desktop chính thức** của [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
(`apps/desktop`, Electron) thành bộ cài cho:

| Nền tảng | File | Máy build (GitHub Actions) |
|----------|------|----------------------------|
| Windows 11 / 10 x64 | `deepseek-harness-<version>-win-x64.exe` (NSIS) | `windows-2025` |
| macOS Apple Silicon | `deepseek-harness-<version>-mac-arm64.dmg` | `macos-15` |
| macOS Intel | `deepseek-harness-<version>-mac-x64.dmg` | `macos-15-intel` |

Mã nguồn dsh được lấy nguyên từ repo chính thức tại thời điểm build; repo này chỉ chứa
workflow và một bản vá nhỏ để build **không cần chứng chỉ ký số**. Đây là bản build
không chính thức, không được DeepSeek xác nhận.

## Tải về

Vào mục **Releases** của repo này và tải file đúng với máy của bạn.

### Cài trên macOS

1. Mở file `.dmg`, kéo **DeepSeek Harness** vào **Applications**.
2. Lần mở đầu tiên macOS sẽ chặn vì ứng dụng chưa được Apple notarize. Chọn một trong hai cách:
   - **System Settings → Privacy & Security** → cuộn xuống, bấm **Open Anyway** cạnh dòng
     “DeepSeek Harness was blocked…”, rồi mở lại ứng dụng.
   - Hoặc chạy trong Terminal:

     ```bash
     xattr -dr com.apple.quarantine "/Applications/DeepSeek Harness.app"
     ```

3. Bản macOS **không tự cập nhật** (Squirrel.Mac không chấp nhận bản ký ad-hoc) —
   khi có phiên bản mới, tải `.dmg` mới và cài đè.

### Cài trên Windows

1. Chạy `deepseek-harness-<version>-win-x64.exe`.
2. SmartScreen có thể hiện *“Windows protected your PC”* → bấm **More info → Run anyway**.
3. Chọn thư mục cài đặt và hoàn tất. Ứng dụng tự kiểm tra bản mới từ GitHub Releases
   của repo này (menu **Check for Updates…**).

### Lần chạy đầu

1. **Settings → Models** → dán DeepSeek API key (lấy tại <https://platform.deepseek.com/api_keys>) → Save.
2. **Choose workspace** → chọn thư mục dự án → bắt đầu một session.

Ứng dụng dùng chung dữ liệu (session, cài đặt, API key) với dsh CLI trong `~/.dsh`
(`%USERPROFILE%\.dsh` trên Windows).

## Build bằng GitHub Actions

**Actions → Build desktop → Run workflow**:

- `upstream_ref`: tag hoặc branch của `deepseek-ai/deepseek-harness`
  (xem [danh sách tag](https://github.com/deepseek-ai/deepseek-harness/tags), ví dụ `dsh-v0.1.5-rc.1`).
- `release`: tick để đăng bộ cài lên GitHub Releases với tag `v<version>`.

Mỗi target chạy lệnh đóng gói chính thức `pnpm run package:desktop:<target>`, nên file cài
kèm sẵn Node.js, pnpm và toàn bộ dsh (cài offline ở lần mở đầu). Artifact của từng target
cũng được đính kèm vào lần chạy workflow.

## Build bản macOS ngay trên máy

```bash
./scripts/build-local-mac.sh dsh-v0.1.5-rc.1
```

Cần Node.js ≥ 22.19 và `corepack` (đi kèm Node). Kết quả nằm trong
`.work/upstream/apps/desktop/.desktop-build/targets/mac-<arch>/artifacts/`.

## Bản vá làm gì

[`scripts/apply-unsigned.mjs`](scripts/apply-unsigned.mjs) sửa checkout upstream trước khi đóng gói:

1. Thay `apps/desktop/electron-builder.config.mjs` bằng
   [`overrides/electron-builder.config.mjs`](overrides/electron-builder.config.mjs): giữ nguyên
   file, runtime, seed và cấu hình NSIS; macOS ký ad-hoc, không hardened runtime, không
   notarize, không kênh cập nhật; Windows không ký Authenticode; publish sang GitHub Releases.
2. Trong `apps/desktop/scripts/prepare-seed.ts`, bỏ bước ký lại các file Mach-O trong pnpm
   store bằng Developer ID khi `DSH_DESKTOP_UNSIGNED=1`.

Mỗi chỗ sửa khớp chính xác một đoạn mã upstream; nếu upstream đổi, script dừng với lỗi rõ
ràng thay vì tạo ra bản build hỏng.

## Giới hạn

- Không ký số → cảnh báo Gatekeeper/SmartScreen ở lần mở đầu; không dùng được cho phân phối đại trà.
- DeepSeek Harness đang ở *developer preview*; mỗi tag upstream có thể thay đổi cách đóng gói.
- Không có bản Windows ARM64 và Linux (upstream không hỗ trợ target này cho desktop).
