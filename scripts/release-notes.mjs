#!/usr/bin/env node
// Write the notes of a published release v<version> of this repository.
//
//   node scripts/release-notes.mjs <owner/repo> <version> <upstream-ref> > notes.md
//
// Reads, through `gh api` (GH_TOKEN in CI):
// - upstream release notes of every dsh-v* version after the previous release
//   here, up to <version>, English half only;
// - this repository's commits between the previous release's tag and v<version>;
// - the release's own assets, for sizes and SHA-256 digests.
// Run it after the release and its assets exist; `gh release edit --notes-file`
// then puts the output on the release.
import { execFileSync } from 'node:child_process'

const UPSTREAM = 'deepseek-ai/deepseek-harness'
// GitHub refuses a release body over 125 000 characters.
const MAX_UPSTREAM_CHARS = 90_000

const [repository, version, upstreamRef] = process.argv.slice(2)
if (!/^[\w.-]+\/[\w.-]+$/u.test(repository ?? '') || !version || !upstreamRef) {
  throw new Error('usage: release-notes.mjs <owner/repo> <version> <upstream-ref>')
}

const api = path => JSON.parse(execFileSync('gh', ['api', path], { encoding: 'utf8', maxBuffer: 64 << 20 }))
const apiPages = path => JSON.parse(execFileSync('gh', ['api', '--paginate', '--slurp', path],
  { encoding: 'utf8', maxBuffer: 64 << 20 })).flat()

// SemVer 2 precedence, enough for x.y.z[-pre.n] (build metadata ignored).
function parse(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+.*)?$/u.exec(v)
  return m ? { core: m.slice(1, 4).map(Number), pre: m[4] ? m[4].split('.') : [] } : undefined
}
function compare(a, b) {
  const x = parse(a)
  const y = parse(b)
  for (let i = 0; i < 3; i++) if (x.core[i] !== y.core[i]) return x.core[i] - y.core[i]
  if (!x.pre.length || !y.pre.length) return y.pre.length - x.pre.length
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const [p, q] = [x.pre[i], y.pre[i]]
    if (p === undefined || q === undefined) return p === undefined ? -1 : 1
    if (p === q) continue
    const [pn, qn] = [/^\d+$/u.test(p), /^\d+$/u.test(q)]
    if (pn && qn) return Number(p) - Number(q)
    if (pn !== qn) return pn ? -1 : 1
    return p < q ? -1 : 1
  }
  return 0
}

const date = iso => iso.slice(0, 10)
const mib = bytes => `${(bytes / 1024 / 1024).toFixed(1)} MB`

// The previous plain build here: SOC builds (.soc.N) and the feed release do not count.
const ours = apiPages(`repos/${repository}/releases?per_page=100`)
  .map(r => r.tag_name).filter(t => /^v\d/u.test(t) && !/\.soc\.\d+$/u.test(t) && parse(t.slice(1)))
const previous = ours.map(t => t.slice(1)).filter(v => compare(v, version) < 0).sort(compare).at(-1)

// Upstream notes are bilingual (中文 then English); keep the English half, and
// point issue numbers and @mentions at upstream without notifying anyone.
function englishNotes(body) {
  const start = body.search(/<h3 id="en-/u)
  return (start >= 0 ? body.slice(start) : body)
    .replace(/<h3 id="[^"]*">(.*?)<\/h3>/gu, '#### $1')
    .replace(/^#{1,3} /gmu, '#### ')
    .replace(/^Full Changelog:.*$/gmu, '')
    .replace(/(^|[\s(])@([A-Za-z0-9][\w-]*)/gu, `$1[$2](https://github.com/$2)`)
    .replace(/(^|[\s(])#(\d+)\b/gu, `$1[#$2](https://github.com/${UPSTREAM}/issues/$2)`)
    .trim()
}

const upstream = apiPages(`repos/${UPSTREAM}/releases?per_page=100`)
  .filter(r => !r.draft && r.tag_name.startsWith('dsh-v') && parse(r.tag_name.slice(5)))
  .filter((r) => {
    const v = r.tag_name.slice(5)
    return compare(v, version) <= 0 && (previous === undefined ? compare(v, version) === 0 : compare(v, previous) > 0)
  })
  .sort((a, b) => compare(b.tag_name.slice(5), a.tag_name.slice(5)))

const lines = []
const push = (...more) => lines.push(...more)

push(`Bản build **không ký** của ứng dụng desktop [DeepSeek Harness](https://github.com/${UPSTREAM}), `
  + `đóng gói từ [\`${UPSTREAM}@${upstreamRef}\`](https://github.com/${UPSTREAM}/tree/${upstreamRef}), `
  + 'không kèm plugin SOC. Đây là bản build không chính thức, không được DeepSeek xác nhận.', '')

push(previous
  ? `## Thay đổi từ upstream (sau bản ${previous})`
  : '## Thay đổi từ upstream', '')
if (upstream.length === 0) {
  push(`Không có ghi chú phát hành upstream cho \`${upstreamRef}\`.`, '')
}
let used = 0
for (const release of upstream) {
  const notes = englishNotes(release.body ?? '')
  const heading = `### [${release.tag_name}](${release.html_url}) · ${date(release.published_at)}`
  if (used + notes.length > MAX_UPSTREAM_CHARS) {
    push(`${heading}`, '', `Xem ghi chú trên [trang release upstream](${release.html_url}).`, '')
    continue
  }
  used += notes.length
  push(heading, '', notes || '_Không có ghi chú._', '')
}
if (previous && upstream.length > 0) {
  push(`So sánh mã nguồn upstream: [dsh-v${previous}...${upstreamRef}]`
    + `(https://github.com/${UPSTREAM}/compare/dsh-v${previous}...${upstreamRef})`, '')
}

push('## Thay đổi của bản đóng gói', '')
push('Mọi bản build ở đây đều vá upstream để:', '',
  '- đóng gói **không cần chứng chỉ ký số** (macOS ký ad-hoc, Windows không ký);',
  '- mở thẳng workspace thay cho cửa sổ chào chỉ dành cho DeepSeek; bước chọn model đầu tiên hướng dẫn **tạo custom provider** cho bất kỳ endpoint OpenAI/Anthropic-compatible nào (vẫn có lựa chọn đăng nhập DeepSeek hoặc nhập DeepSeek API key);',
  '- nâng cấp êm từ các bản SOC 0.1.x: cất profile cũ sang bên, mở lại session có preset đã bị gỡ bằng preset mặc định;',
  `- **cập nhật từ GitHub Releases của repo này**: Windows tự tải và cài bản mới, macOS báo có bản mới và mở trang release.`, '')
if (previous) {
  try {
    const { commits } = api(`repos/${repository}/compare/v${previous}...v${version}`)
    if (commits.length > 0) {
      push(`Thay đổi trong repo đóng gói từ v${previous}:`, '')
      for (const c of commits.toReversed()) {
        push(`- ${c.commit.message.split('\n')[0]} ([\`${c.sha.slice(0, 7)}\`](${c.html_url}))`)
      }
      push('')
    }
  }
  catch {
    // A tag missing on one side: the static list above still says what the build changes.
  }
}

push('## Tải về', '')
const platforms = [
  [/-mac-arm64[^/]*\.dmg$/u, 'macOS Apple Silicon (M1 trở lên)'],
  [/-mac-x64[^/]*\.dmg$/u, 'macOS Intel'],
  [/-win-x64[^/]*\.exe$/u, 'Windows 10/11 x64'],
  [/-win-arm64[^/]*\.zip$/u, 'Windows ARM64 (giải nén, không tự cập nhật)'],
]
const assets = api(`repos/${repository}/releases/tags/v${version}`).assets
const rows = assets.flatMap((asset) => {
  const platform = platforms.find(([pattern]) => pattern.test(asset.name))
  if (!platform) return []
  const digest = asset.digest?.startsWith('sha256:') ? `\`${asset.digest.slice(7)}\`` : '—'
  return [[platform[1], `[${asset.name}](${asset.browser_download_url})`, mib(asset.size), digest]]
})
if (rows.length > 0) {
  push('| Máy | File | Dung lượng | SHA-256 |', '|-----|------|-----------:|---------|')
  for (const row of rows) push(`| ${row.join(' | ')} |`)
  push('')
}

push('## Cài đặt', '',
  '**macOS**', '',
  '1. Mở file `.dmg`, kéo **DeepSeek Harness** vào **Applications**.',
  '2. Ứng dụng chưa được Apple notarize nên lần mở đầu bị chặn. Gỡ cờ quarantine rồi mở lại:', '',
  '   ```bash',
  '   xattr -dr com.apple.quarantine "/Applications/DeepSeek Harness.app"',
  '   ```', '',
  `   hoặc dùng [\`scripts/approve-mac.sh\`](https://github.com/${repository}/blob/main/scripts/approve-mac.sh) (gỡ cờ, kiểm tra chữ ký, mở ứng dụng),`,
  '   hoặc **System Settings → Privacy & Security → Open Anyway**.', '',
  '**Windows**', '',
  '1. Chạy file `.exe`. Nếu SmartScreen hiện *Windows protected your PC*, bấm **More info → Run anyway**.',
  '2. Lần mở đầu mất vài phút để cài runtime đi kèm vào `%USERPROFILE%\\.dsh`; đừng mở ứng dụng lần thứ hai trong lúc đó.', '',
  '## Cập nhật', '',
  '- **Windows**: ứng dụng tự kiểm tra GitHub Releases của repo này (**Check for Updates…**), tải và cài bản mới sau khi bạn xác nhận.',
  '- **macOS**: ứng dụng báo khi có bản mới và mở trang release; tải `.dmg` mới, cài đè, rồi gỡ cờ quarantine như trên.',
  '',
  `Dữ liệu (session, cài đặt, API key) nằm trong \`~/.dsh\` và được giữ nguyên khi cài đè. Hướng dẫn đầy đủ: [README](https://github.com/${repository}#readme).`)

process.stdout.write(`${lines.join('\n')}\n`)
