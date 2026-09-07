## Why

Нужен самостоятельный локальный AppSec-инструмент с полностью контролируемым исходным кодом orchestration, нормализации и отчётности. Он должен запускать существующие open-source scanners в изолированных контейнерах, объединять их несовместимые результаты и явно сообщать не только находки, но и пробелы покрытия.

## What Changes

- Создать новый Go CLI `secscan` для Linux и macOS.
- Поддержать Docker и Podman, rootless-режим, read-only mount репозитория, ограничение привилегий и контролируемый network access.
- Реализовать scanner personas Gitleaks, Python SAST, TypeScript SAST, Semgrep, Trivy, Grype, Checkov, Checkov Terraform, OSV-Scanner, Zizmor, Bearer, cppcheck, Gradle Catalog, Gradle Scripts, refreshVersions, KICS, Poutine и OCI Images.
- Нормализовать scanner outputs в собственную versioned schema v1 с детерминированными fingerprint, ordering и deduplication.
- Реализовать coverage accounting, scanner failures, skipped inputs, unread manifests, unchecked languages, ignored и untracked directories.
- Реализовать severity/test-data filters, project suppressions, native scanner waivers, baselines, scoped scans и token budget.
- Генерировать minified JSON, offline HTML и SARIF 2.1.0 из одной канонической модели.
- Добавить opt-in LLM brief/explain с обязательным удалением secrets и изоляцией от инструкций сканируемого репозитория.
- Поддержать headless CI execution без изменения exit code из-за самих findings.
- Показывать интерактивный scanner dashboard в TTY и стабильные progress events в CI.
- Добавить explicit `secscan update` для pinned images и атомарных advisory snapshots; обычный scan не выполняет загрузки.
- Реализовать оставшиеся personas шестью проверяемыми outcomes: preparation, CI, IaC, dependencies, SAST, static Gradle/OCI.
- Использовать Bearer только из upstream image на amd64; на arm64 сообщать skipped. Semgrep использует собственные MIT rules и upstream runtime image без redistribution.

## Open-source publication

Publish the project as public `sagolubev/secscan` under MIT for project-owned
code. Preserve third-party licenses. GitHub Actions must check source,
traceability, real scanner boundaries and four standalone build targets.
Tag releases publish only the secscan executables and checksum metadata;
scanner engines/databases remain explicit runtime downloads. Assess the GRACE
pilot from repository evidence without claiming unmeasured time savings.

## Trivy export integration

Add `--trivy-reports DIR` for repository dependency reports: CycloneDX 1.6 JSON
for Dependency-Track 4.12+ and Generic Issues JSON for SonarQube Server 10.3+.
Use the full package inventory from the existing offline Trivy scan, including
packages without vulnerabilities. Keep JSON stdout unchanged. Write a new
output directory outside the scanned worktree; do not upload files or require
service credentials. Incomplete Trivy extraction must fail the requested export.
This is one feature outcome with a real Trivy-to-files acceptance seam;
Standard artifacts and Comprehensive verification remain applicable.

## Binary installer

Publish a self-contained POSIX `install.sh` for one-command installation from
GitHub. Detect Linux/macOS and amd64/arm64, resolve the latest stable release
once or accept `--version`, verify the selected binary against SHA256SUMS,
and install to `~/.local/bin` or `--dir`. Preserve an existing installation on
failure and replace it only with a verified executable. Do not install runtimes,
use sudo, edit shell profiles or change the release asset set. This single
outcome includes installer tests on Linux/macOS and a real published-binary
installation check; the existing feature profile and verification depth apply.

## Coverage and product baselines

Complete traversal disclosure with eligible tracked/untracked/ignored file and
byte counts, directory summaries and explicit omissions. Report known code and
dependency inputs without a successful applicable analysis, and disclose
unclassified files. Give Gitleaks the same safe nonignored staged inventory as
other filesystem scanners. Add concise GRACE module maps and boundary contracts
in changed code, linked to the existing OpenSpec and tests.

Then add --write-baseline and --baseline for portable versioned snapshots of
unfiltered normalized findings. Preserve secret/error findings, show new and
expanded findings, and reject incompatible snapshots. Compare relative paths
across checkouts. Baseline files inside the worktree are explicit control inputs
excluded from scanner staging and disclosed in traversal metadata. Existing
Trivy integration exports remain unfiltered. Filesystem publication and decoder
validation must preserve the current trust boundary.

## Reports, project filtering and scopes

The next delivery sequence is cancellation-test reliability, offline HTML and
full SARIF export, declarative project suppressions, then explicit file/directory
scopes. Keep JSON stdout, unfiltered baseline snapshots and Trivy exports
compatible. Reuse the verified pinned-directory file publication boundary.
HTML/SARIF is the vertical report outcome; filtering must preserve both the
complete scan and the visible report. Scopes must state which scanners actually
narrowed their inputs. Token budgets, Git history, custom cached rules, broader
runtime coverage and LLM annotation remain separate backlog outcomes.

## Capabilities

### New Capabilities

- `scanner-orchestration`: безопасный параллельный запуск scanner containers.
- `progress-reporting`: интерактивный TTY dashboard и plain CI events.
- `finding-normalization`: единая модель findings, locations, advisories и coverage.
- `report-filtering`: suppressions, waivers, baselines, scopes и budget accounting.
- `report-rendering`: JSON v1, HTML и SARIF.
- `llm-analysis`: opt-in brief и per-finding explanation.
- `reproducible-scans`: digest-pinned images, cached rules и pinned advisory feeds.

### Modified Capabilities

- Нет: проект создаётся с нуля.

## Impact

- Требуется установленный Docker или Podman daemon.
- Первичная загрузка scanner images и advisory databases потребует сеть и несколько гигабайт cache.
- Проект не обещает совместимость с DietSec Schema 4, fingerprints или baselines.
- Scanner engines остаются отдельными third-party projects; secscan хранит собственный orchestration и adapter code.
- Hosted/managed service не входит в первую версию из-за иной threat model и ограничений лицензий third-party rule corpora.

## Workflow Profile

- Profile: feature
- Artifact depth: Standard
- Verification depth: Comprehensive
- Walking skeleton: Required
- Skeleton rationale: первый вертикальный результат должен доказать безопасный container execution, parsing, normalization и JSON contract до расширения на остальные adapters.
- Human approval: Yes
