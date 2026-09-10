/**
 * First-start progress window (deepseek-harness-desktop). Installing the seed
 * writes tens of thousands of files before the main window exists, which takes
 * minutes on Windows; without this window the application looks like it never
 * started. The page runs no script and its spinner is compositor-driven, so it
 * keeps moving while the seed extraction blocks the main thread.
 * @param localeName - Electron application locale.
 * @returns the shown window; the caller destroys it once the main window loads.
 */
async function openSetupWindow(localeName: string): Promise<BrowserWindow> {
  const chinese = localeName.toLowerCase().startsWith('zh')
  const title = chinese ? '正在准备 DeepSeek Harness…' : 'Setting up DeepSeek Harness…'
  const detail = chinese
    ? '首次启动需要安装内置运行环境，可能需要几分钟，请保持此窗口打开。'
    : 'The first launch installs the bundled runtime. This can take a few minutes; please keep this window open.'
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title><style>
body{margin:0;height:100vh;display:flex;align-items:center;gap:20px;padding:0 32px;box-sizing:border-box;font:14px/1.5 -apple-system,"Segoe UI",system-ui,sans-serif;background:#fff;color:#1f2328;-webkit-app-region:drag;user-select:none}
.spin{flex:none;width:28px;height:28px;border:3px solid #d0d7de;border-top-color:#4d6bfe;border-radius:50%;animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:16px;font-weight:600;margin:0 0 4px}
p{margin:0;color:#57606a}
@media (prefers-color-scheme:dark){body{background:#1e1f22;color:#e6edf3}p{color:#9aa4ae}.spin{border-color:#3a3f45;border-top-color:#6d87ff}}
</style></head><body><div class="spin"></div><div><h1>${title}</h1><p>${detail}</p></div></body></html>`
  const window = new BrowserWindow({
    width: 500,
    height: 150,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    frame: false,
    center: true,
    show: false,
    title,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      javascript: false,
    },
  })
  await window.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`)
  window.show()
  // Give the compositor a frame before synchronous seed extraction blocks the main thread.
  await new Promise(resolve => setTimeout(resolve, 300))
  return window
}

