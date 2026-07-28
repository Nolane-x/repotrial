# ⚖ RepoTrial — Xét xử repository AI agent

RepoTrial là dự án độc lập để kiểm định repository AI agent bằng **bằng chứng xác định**, không cần ForgeOS, API key, LLM hay tài khoản cloud. Khi kết nối ForgeOS v0.6+, nó nhận thêm security engine thứ hai, bằng chứng kernel/runtime và RoutePlan khắc phục có nghĩa vụ bằng chứng.

## Khởi động nhanh

Yêu cầu Node.js 22.14+ hoặc Node.js 24. Không có dependency npm runtime.

```bash
npm install
node bin/repotrial.mjs scan duong-dan-repo --forgeos off
node bin/repotrial.mjs serve .repotrial
```

Chặn CI từ mức `RECKLESS`:

```bash
repotrial scan . --forgeos off --runtime off --supply-chain offline --fail-on reckless --json
```

## Quét đầy đủ

```bash
repotrial keygen --output .repotrial-keys

repotrial scan . \
  --runtime sandbox \
  --supply-chain osv \
  --baseline-ref origin/main \
  --fail-on-new reckless \
  --signing-key .repotrial-keys/repotrial-private.pem \
  --cosign \
  --forgeos cli \
  --forgeos-root ../forge-os \
  --forgeos-depth full
```

Các provider có thể chạy code, dùng mạng hoặc ký đều phải được bật rõ ràng. Nếu một provider không sẵn sàng, RepoTrial ghi đúng trạng thái thay vì giả vờ đã kiểm tra.

## Các lớp năng lực

### Phân tích tĩnh đa agent

RepoTrial nhận diện `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, GitHub Copilot, Cursor, Cline, Windsurf, Continue, MCP, hook, package script, quyền shell, secret reference, egress và approval gate. JSON, YAML và TOML được parse có giới hạn, gồm anchor/alias/merge key, block scalar, custom tag, dotted table, array-of-table, inline collection và multiline string.

### Detonation runtime trong sandbox

`--runtime sandbox` sao chép repository sang root filesystem dùng một lần rồi chạy các lifecycle script hoặc script được chỉ định. Trên Linux hỗ trợ, nó tách user, mount, UTS, IPC, network, PID và cgroup namespace; dùng chroot; không truyền secret environment; giới hạn thời gian/output/process/file; chặn công cụ mạng; ghi nhận Node network/DNS/child process; và so sánh hash filesystem trước/sau.

Repository gốc không bao giờ là thư mục thực thi. Trước khi sao chép, RepoTrial giới hạn mặc định 20.000 file và 256 MiB (`--runtime-max-source-files`, `--runtime-max-source-bytes`), đồng thời loại thư mục output đang dùng. Xem [docs/runtime-sandbox.md](docs/runtime-sandbox.md).

### SBOM, CVE, license và container

Chế độ offline đọc lockfile của npm, pnpm, Yarn, Python requirements, Poetry, uv, Pipfile, Cargo, Go, Composer, Gem và Dockerfile; tạo CycloneDX 1.6 và thống kê license. `--supply-chain osv` dùng OSV `querybatch` qua HTTPS có giới hạn. Có thể nối Trivy/Grype/SARIF qua adapter command mà không biến chúng thành dependency bắt buộc.

### Differential PR

```bash
repotrial scan . --baseline-ref origin/main --fail-on-new reckless
repotrial diff old/verdict.json new/verdict.json --json
```

Finding được chia thành `new`, `existing`, `resolved`; SARIF có `baselineState`; CI có thể chỉ chặn lỗi mới bằng exit code `3`.

### Chữ ký và nguồn gốc

Mỗi scan tạo SHA-256 artifact proof và kiểm tra lại các invariant: hash artifact, report receipt, đường dẫn tương đối, verdict xác định, `TRUSTED` phải có coverage hoàn chỉnh. RepoTrial hỗ trợ Ed25519 DSSE cục bộ, in-toto/SLSA provenance v1 và Cosign/Sigstore bằng khóa hoặc OIDC keyless.

## Artifact

```text
.repotrial/
├── report.html
├── verdict.json
├── evidence.json
├── repotrial-badge.svg
├── forgeos-agent-surface.json
├── repotrial.sarif
├── runtime.json
├── supply-chain.json
├── sbom.cdx.json
├── differential.json
├── artifact-proof.json
├── provenance.intoto.json
├── provenance.dsse.json
└── provenance.sigstore.json
```

Không phải scan nào cũng tạo đủ artifact tùy chọn. Dữ liệu do repository kiểm soát được đưa qua redaction chung; đường dẫn tuyệt đối của máy bị ẩn mặc định.

## ForgeOS Powered

Đặt hai repository cạnh nhau:

```text
workspace/
├── forge-os/
└── repotrial/
```

```bash
repotrial forgeos-doctor --forgeos-root ../forge-os
repotrial scan . --forgeos cli --forgeos-root ../forge-os --forgeos-depth full
```

Chế độ `full` nhập security report và SHA-256 của ForgeOS, version/inventory kernel, adversarial corpus evidence và RoutePlan khắc phục gồm technique, provider, outcome và evidence obligation.

Sidecar:

```bash
export REPOTRIAL_BRIDGE_TOKEN='token-dai-ngau-nhien'
export FORGEOS_ROOT='../forge-os'
node integrations/forgeos/bridge-server.mjs

repotrial scan . \
  --forgeos http \
  --forgeos-url http://127.0.0.1:8791 \
  --forgeos-token "$REPOTRIAL_BRIDGE_TOKEN" \
  --forgeos-depth full
```

Bridge dùng protocol `repotrial.forgeos.bridge.v1`, bind loopback mặc định, có token, giới hạn request/output/thời gian và từ chối HTTP từ xa không mã hóa trừ khi người vận hành chủ động cho phép.

## GitHub Action

```yaml
name: RepoTrial
on: [pull_request, push]
permissions:
  contents: read
  security-events: write
  id-token: write
jobs:
  trial:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: casioreview20-glitch/repotrial@v1
        with:
          exclude-paths: tests/fixtures
          baseline-ref: origin/main
          fail-on-new: reckless
          supply-chain-mode: osv
          sigstore: 'true'
          upload-sarif: 'true'
```

Action trả verdict, score, số finding mới, HTML, SARIF, SBOM, proof, DSSE, Sigstore, receipt và thông tin ForgeOS.

## Docker

```bash
docker build -t repotrial:0.4.1 .
docker run --rm repotrial:0.4.1 version
```

Image chạy bằng user `node`, không phải root. Runtime sandbox bên trong container phụ thuộc việc host cho phép unprivileged namespaces; nếu không, RepoTrial trả `runtime.unavailable`, không hạ mức cách ly.

## Giới hạn vận hành quan trọng

```text
--exclude <duong-dan-a,duong-dan-b>
--runtime-max-source-files <n>
--runtime-max-source-bytes <n>
--max-files <n>
--max-file-bytes <n>
--max-total-bytes <n>
--osv-timeout <ms>
--container-scanner-command <path>
--baseline-ref <git-ref>
--fail-on-new cautious|reckless|dangerous
```

Chạy `repotrial scan --help` để xem toàn bộ điều khiển production, gồm ForgeOS bridge, signing, Cosign và provenance.

## Ý nghĩa verdict

- `TRUSTED`: không chứng minh được tín hiệu nguy hiểm đã biết trong toàn bộ phạm vi đã đọc; **không phải chứng nhận an toàn**.
- `CAUTIOUS`: rủi ro thấp hơn, provider không chắc chắn hoặc coverage thiếu.
- `RECKLESS`: nhiều tín hiệu mức cao hoặc tổng rủi ro lớn.
- `DANGEROUS`: có bằng chứng critical hoặc vượt ngưỡng nguy hiểm.
- `UNPROVEN`: không có bằng chứng đủ để đánh giá.

RepoTrial tạo hồ sơ có thể kiểm tra lại, không thay thế review bảo mật, sandbox chuyên dụng, EDR hay kiểm toán con người. Xem [SECURITY.md](SECURITY.md).
