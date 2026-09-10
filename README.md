# DeepSeek Harness Desktop — bản build không ký cho Windows 11 & macOS

Đóng gói **ứng dụng desktop chính thức** của [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness)
(`apps/desktop`, Electron) thành bộ cài cho:

| Nền tảng | File | Máy build (GitHub Actions) |
|----------|------|----------------------------|
| Windows 11 / 10 x64 | `deepseek-harness-<version>-win-x64.exe` (NSIS) | `windows-2025` |
| macOS Apple Silicon | `deepseek-harness-<version>-mac-arm64.dmg` | `macos-15` |
| macOS Intel | `deepseek-harness-<version>-mac-x64.dmg` | `macos-15-intel` |

Mã nguồn dsh được lấy nguyên từ repo chính thức tại thời điểm build; repo này chỉ chứa
workflow và các bản vá nhỏ. Đây là bản build không chính thức, không được DeepSeek xác nhận.

So với upstream, bản build này:

1. **Không cần chứng chỉ ký số** (macOS ký ad-hoc, Windows không ký).
2. **Hướng dẫn tạo custom model provider ở lần mở đầu**: khi chưa có provider nào dùng được,
   ứng dụng hiện hộp thoại từng bước để tạo provider cho bất kỳ endpoint OpenAI/Anthropic-compatible
   nào (vẫn có lựa chọn nhập DeepSeek API key như cũ).
3. **Web search qua DuckDuckGo**: preset mặc định `Standard (DuckDuckGo)` bỏ tool `web_search`
   và dạy model tìm kiếm bằng `https://html.duckduckgo.com/html/?q=…` + `web_fetch`.

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

1. Nếu chưa có model provider, hộp thoại **Set up a model provider** hiện ra:
   - **Create a custom provider** → điền theo 5 bước: Provider ID, Base URL + API protocol,
     API key, Models (**Fetch available models** hoặc nhập tay), **Create**.
   - Hoặc **Use a DeepSeek API key** (lấy tại <https://platform.deepseek.com/api_keys>).
2. Chọn model vừa tạo trong ô chọn model dưới khung soạn tin.
3. **Choose workspace** → chọn thư mục dự án → bắt đầu một session.

Ứng dụng dùng chung dữ liệu (session, cài đặt, API key) với dsh CLI trong `~/.dsh`
(`%USERPROFILE%\.dsh` trên Windows).

## Preset web search DuckDuckGo

Bản desktop đã có sẵn preset `standard-ddg` và dùng nó làm mặc định cho session mới
(đổi lại trong bộ chọn preset khi tạo session, hoặc `agent-presets.default` trong `~/.dsh/settings.yaml`).

Với **dsh CLI** (hoặc bản desktop chính thức), cài preset vào `~/.dsh` bằng file
`deepseek-harness-ddg-preset.zip` trong Releases (hoặc từ repo này):

```bash
./scripts/install-preset.sh              # macOS / Linux
```

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-preset.ps1   # Windows
```

Script chép preset vào `~/.dsh/.agent-presets/standard-ddg/` và đặt nó làm mặc định trong
`~/.dsh/settings.yaml` (thêm `--no-default` / `-NoDefault` để chỉ cài). Session đang chạy giữ preset cũ.

Preset được sinh từ preset `standard` của upstream bằng
[`scripts/make-ddg-preset.mjs`](scripts/make-ddg-preset.mjs): chính sách tìm kiếm nằm trong
persona suffix của system prompt, và `tool-web` đặt `search: false`.

## Build bằng GitHub Actions

**Actions → Build desktop → Run workflow**:

- `upstream_ref`: tag hoặc branch của `deepseek-ai/deepseek-harness`
  (xem [danh sách tag](https://github.com/deepseek-ai/deepseek-harness/tags), ví dụ `dsh-v0.1.5-rc.1`).
- `release`: tick để đăng bộ cài lên GitHub Releases với tag `v<version>`.

Mỗi target chạy lệnh đóng gói chính thức `pnpm run package:desktop:<target>`, nên file cài
kèm sẵn Node.js, pnpm và toàn bộ dsh (cài offline ở lần mở đầu).

## Build bản macOS ngay trên máy

```bash
./scripts/build-local-mac.sh dsh-v0.1.5-rc.1
```

Cần Node.js ≥ 22.19 và `corepack` (đi kèm Node). Kết quả nằm trong
`.work/upstream/apps/desktop/.desktop-build/targets/mac-<arch>/artifacts/`.

## Bản vá làm gì

[`scripts/patch-upstream.mjs`](scripts/patch-upstream.mjs) sửa checkout upstream trước khi đóng gói:

| Thay đổi | File upstream |
|----------|---------------|
| Cấu hình đóng gói không ký, publish sang GitHub Releases, macOS không có kênh cập nhật | `apps/desktop/electron-builder.config.mjs` ← [`overrides/electron-builder.config.mjs`](overrides/electron-builder.config.mjs) |
| Bỏ bước ký lại Mach-O của seed bằng Developer ID khi `DSH_DESKTOP_UNSIGNED=1` | `apps/desktop/scripts/prepare-seed.ts` |
| Wizard tạo custom provider ở lần mở đầu | `packages/client/ui-settings-models/src/client/DeepSeekOnboardingDialog.tsx` ← [`overrides/ui-settings-models/`](overrides/ui-settings-models) |
| Chuỗi giao diện của wizard (English + 中文) | `packages/client/ui-settings-models/src/client/locales.ts` |
| Preset `standard-ddg` trong bộ preset có sẵn | `packages/preset/agent-presets/presets/standard-ddg/` |
| Preset mặc định của bản desktop = `standard-ddg` | `apps/desktop-host/config/desktop.cordis.patch.yml` |

File bị thay thế phải khớp mã SHA-256 ghi trong [`overrides/manifest.json`](overrides/manifest.json),
và mỗi đoạn vá phải khớp đúng một đoạn mã upstream; nếu upstream đổi, script dừng với lỗi rõ ràng
thay vì tạo ra bản build hỏng.

## Giới hạn

- Không ký số → cảnh báo Gatekeeper/SmartScreen ở lần mở đầu; không dùng được cho phân phối đại trà.
- Giao diện ứng dụng chỉ có tiếng Anh và tiếng Trung (theo upstream).
- DeepSeek Harness đang ở *developer preview*; mỗi tag upstream có thể thay đổi cách đóng gói.
- DuckDuckGo có thể chặn truy vấn tự động; khi đó model không lấy được kết quả tìm kiếm.
- Không có bản Windows ARM64 và Linux (upstream không hỗ trợ target này cho desktop).
