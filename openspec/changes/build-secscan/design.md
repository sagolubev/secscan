## Context

`secscan` создаётся с нуля как локальный Go CLI. Первый вертикальный результат
должен доказать полный путь от CLI до реального container runtime, Gitleaks,
нормализации и детерминированного JSON. Репозиторий одновременно проводит
GRACE-пилот: связи requirement → component → test, фазовые evidence и
проверяемый scope.

OpenSpec остаётся источником требований и design, а Beads — задач, зависимостей
и evidence. Полная модель `.grace` не вводится. Пилот использует один тонкий
repo-local verifier и не создаёт второй lifecycle.

## Goals / Non-Goals

**Goals:**

- Реализовать один реальный Gitleaks scan через Docker или Podman.
- Реализовать отдельные Python и TypeScript SAST jobs через Opengrep.
- Показывать live scanner dashboard в TTY и plain events в CI.
- Добавить все оставшиеся scanner personas на уже проверенной container boundary.
- Зафиксировать минимальный schema-v1 JSON contract.
- Удалить secret values и source snippets до выхода из adapter boundary.
- Проверить security options container invocation без shell interpolation.
- Связать требования с components и tests.
- Выдавать `baseline`, `target` и `final` evidence, привязанное к Git-состоянию.
- Проверять полный changed-file set относительно declared scope.

**Non-Goals for the initial walking skeleton (later outcomes extend it):**

- HTML, SARIF, product baselines, suppressions и LLM analysis.
- Универсальный workflow framework или совместимость с GRACE CLI.
- Автоматический запуск команд из недоверенного репозитория.

## Decisions

### 1. Один Go module и явные границы

Первый срез использует:

- `cmd/secscan` — flags, exit codes, stdout/stderr.
- `internal/container` — обнаружение Docker/Podman и безопасный argv.
- `internal/gitleaks` — Gitleaks invocation и parsing.
- `internal/discovery` — NUL-safe Git file inventory и temporary target trees.
- `internal/opengrep` — Python/TypeScript invocation, parsing и rule metadata.
- `internal/orchestrator` — bounded parallel jobs и partial-failure merge.
- `internal/progress` — event state, plain renderer и live TTY dashboard.
- `internal/report` — schema-v1 types, redaction, sorting и JSON.
- `cmd/tracecheck` — development verifier для GRACE-пилота.

`main` только преобразует CLI input в вызов пакета и отображает результат.
Interfaces добавляются со стороны consumer только когда тесту или второй
реализации действительно нужна подмена.

**Alternatives considered:**

- Один большой `main.go`: отклонён, потому что смешивает process execution,
  parsing и wire contract.
- Registration/plugin framework: не нужен; три известных jobs собираются в
  composition root явным списком.

### 2. Gitleaks — единственный scanner walking skeleton

Gitleaks `v8.30.1` запускается из multi-platform image
`ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f`.
Repository монтируется read-only, report пишется в отдельный temporary
directory. Container получает
`no-new-privileges`, не получает container socket и работает с отключённой
сетью. Команда строится как argv и запускается через `exec.CommandContext`.

Image pull выполняется только командой `secscan update`. При scan используется
`--pull never`; отсутствующий image даёт failed coverage с указанием update.
Фактически использованный digest записывается в coverage metadata.

Walking skeleton использует `gitleaks dir /repo`: он сканирует working tree и
не требует монтировать Git common directory, которое у linked worktree может
находиться за пределами root. Gitleaks получает `--exit-code 0` и
`--redact=100`, чтобы findings не выглядели как scanner failure, а scanner logs
не раскрывали секрет. Timeout, невозможность запуска, malformed JSON и
отсутствующий report становятся error finding и failed coverage. Git-history
scan остаётся отдельным последующим outcome.

**Alternatives considered:**

- Trivy: отложен, потому что advisory DB и cache добавляют вторую внешнюю
  границу до доказательства базового pipeline.
- Fixture-only adapter: отклонён как недостаточный walking skeleton.

### 3. Redaction происходит на входе в canonical model

Adapter декодирует Gitleaks JSON во временный scanner DTO. Преобразование в
canonical `Finding` переносит только rule ID, redacted message, file location,
origin `working_tree` и вычисленный fingerprint. Secret value и source snippet
не входят в canonical types, поэтому их нельзя случайно сериализовать позже.

Тестовые fixtures содержат только синтетические canary values. Ошибки parsing
не включают исходный JSON.

### 4. Детерминированный минимальный report

Schema v1 для walking skeleton содержит:

- `schemaVersion`;
- `repository`;
- `scanners` с status и измеряемым coverage;
- `findings` с kind, rule, location, fingerprint и sources.

Findings сортируются по fingerprint, затем path и line. Fingerprint строится из
канонических несекретных полей через SHA-256. JSON формируется `encoding/json`
без сторонних libraries.

Полная schema для dependency deduplication, suppressions, SARIF и token budget
расширяется последующими outcomes без изменения уже опубликованных полей.

### 5. Trace manifest — проекция, а не новый источник требований

`openspec/changes/build-secscan/trace.json` содержит:

- schema version и change name;
- `targetOutcome` с точным ID дочерней Beads-задачи walking skeleton;
- полный список точных пар requirement/scenario из delta spec;
- для каждого scenario — disposition `target` с component/test paths либо
  `deferred` со ссылкой на Beads issue;
- единственный `baselineCommit`;
- declared implementation scope, governance scope и evidence sinks;
- команды для `baseline`, `target` и `final`.

Manifest не содержит текст требований, task status или повтор design.
`baselineCommit` задаётся в manifest один раз после завершения самого
tracecheck и до product implementation. CLI-флаг не может его переопределить.
Verifier проверяет, что commit существует и является ancestor текущего `HEAD`.
`targetOutcome` не выводится из epic `.br-link`: verifier требует конкретный
child issue и проверяет, что он принадлежит связанному epic.

`cmd/tracecheck` сам извлекает иерархию `### Requirement:` /
`#### Scenario:` из delta spec и требует точного однократного покрытия каждого
scenario. Для target entries он проверяет paths; deferred entry без Beads issue
невалидна. Verifier запускает только явно выбранную фазу с `--run`, без shell,
и выводит один JSON evidence document.

### 6. Evidence привязано к рабочему состоянию

Evidence содержит phase, baseline commit, `checks[]` с argv, cwd, exit code и
duration каждого запуска, aggregate status, implementation state identity и
canonical authority hash связанной Beads-задачи.
Для `target` и `final` verifier использует только `baselineCommit` из manifest.
Identity включает baseline commit и SHA-256 содержимого всех изменённых
implementation и authority paths, включая разрешённые untracked files.
Verifier перечисляет untracked paths, но не читает файлы вне declared scope.
Известные secret/config paths исключаются из content hashing и вызывают ошибку,
если попали в change scope.

Baseline фиксируется после commit с рабочим tracecheck и до product code; этот
commit записывается в `trace.json` и Beads outcome. Target доказывает текущий
outcome независимо от промежуточных implementation commits. Final
последовательно запускает весь объявленный command gate без shell и
останавливается на первом failed check.

Каждый изменённый path обязан входить в implementation scope, governance scope
или evidence sinks. Authority paths (`design.md`, delta spec, `trace.json`,
`.stale.json`) входят в state identity. Единственный evidence sink —
`.beads/issues.jsonl`: он перечисляется в evidence, но исключается из
implementation state identity.

Перед запуском checks verifier получает `targetOutcome` через `br show --json`,
проверяет его parent against `.br-link` и строит canonical authority hash из
issue ID, parent ID, title, description, acceptance criteria и dependency IDs.
Notes/evidence, timestamps и lifecycle status в hash не входят: они меняются
при записи результата и закрытии задачи, но не меняют согласованный инженерный
outcome. Изменение содержательных полей делает предыдущее evidence несвежим.
Другие evidence sinks и исключения не поддерживаются. Отдельное committed
evidence-хранилище не создаётся.

### 7. Scope вычисляется из Git, а не из памяти агента

Verifier сравнивает baseline commit со всем текущим состоянием: commits после
baseline, staged, unstaged, deleted, renamed и untracked paths. Для rename
проверяются и исходный, и целевой path. Каждый path должен совпасть с
implementation scope, governance scope или единственным evidence sink. На
первом этапе scope поддерживает только точные paths и directory prefixes; glob
engine не создаётся.

Несовпавшие paths делают проверку красной. Reviewer отдельно проверяет смысл
изменений: принадлежность scope не доказывает корректность.

### 8. Verification идёт снаружи внутрь

TDD начинается с CLI boundary и одного synthetic repository:

1. RED: CLI acceptance ожидает один JSON document без canary secret.
2. GREEN: минимальная wiring до fake process seam.
3. RED/GREEN: Gitleaks parser и canonical redaction.
4. RED/GREEN: безопасный Docker/Podman argv.
5. Real acceptance: pre-pulled/pinned Gitleaks image и fixture repository.

Focused tests не требуют daemon. Real container acceptance может быть skipped
при отсутствии runtime, но walking skeleton остаётся незавершённым до
успешного запуска.

### 9. Progress — события отдельно от rendering

`internal/progress` принимает scanner events:

- `queued`;
- `discovering`;
- `preparing`;
- `scanning`;
- `reading`;
- `normalizing`;
- `done`, `skipped` или `failed`.

Scanner packages сообщают события через узкий `Sink`. Они не знают о TTY,
цветах или ANSI. `plain` renderer немедленно пишет одну стабильную строку на
event. `tty` renderer хранит последние states и events, обновляет фиксированный
dashboard не чаще 10 раз в секунду и рисует elapsed-time bars. Bar показывает
только прошедшее время относительно самого долгого активного scanner и никогда
не называется процентом завершения.

`--progress auto|tty|plain|off` управляет renderer. `auto` использует
`golang.org/x/term.IsTerminal` и выбирает TTY только при `TERM != dumb`;
`NO_COLOR` сохраняет выбранный renderer, но отключает цвета. Non-TTY всегда
использует plain events. `signal.NotifyContext` обрабатывает interrupt/SIGTERM,
а renderer восстанавливает cursor до возврата из `run`, раньше `os.Exit`.

Renderer получает injected clock и ticker. Plain events имеют возрастающий
sequence и стабильный `key=value` порядок. TTY renderer запрашивает terminal
width перед redraw, сокращает labels по rune boundaries и переключается на
compact layout ниже 60 columns. Он очищает и перерисовывает только собственный
фиксированный region; resize и wrapping не повреждают предшествующий вывод.

### 10. Python и TypeScript — два jobs одного Opengrep engine

`internal/discovery` получает tracked и untracked nonignored files через
`git ls-files --cached --others --exclude-standard -z` и формирует два
отсортированных набора:

- Python: `.py`, `.pyi`;
- TypeScript: `.ts`, `.tsx`, `.mts`, `.cts`.

NUL-safe parser отклоняет absolute paths, traversal и symlinks. Выбранные
regular files копируются в temporary target tree с сохранением относительных
paths; Opengrep получает только `/target`, поэтому имя файла не может стать
CLI option. Ignored files не копируются и учитываются отдельными file/byte
counts в exclusions.

`python-sast` и `typescript-sast` являются отдельными jobs, поэтому имеют
собственные progress, timeout, status, findings и coverage. Оба используют
одинаковый Opengrep runtime, но разные rule files. Job без файлов завершается
`skipped` без запуска container.

`internal/orchestrator` один раз готовит Opengrep image до fan-out, затем
запускает Gitleaks и применимые language jobs с
ограниченной concurrency. Каждый job получает дочерний context и собственный
timeout. Partial failure сохраняет успешные результаты и добавляет failed
scanner coverage; общий exit code остаётся `0`, если хотя бы один scanner
успешен. Перед JSON encoding scanner coverage сортируется по scanner name, а
findings — по существующему deterministic ключу.

### 11. Project-owned Opengrep image

У Opengrep нет подтверждённого официального container image. Бинарник
встраивает `scanner/opengrep/assets`, материализует build context в cache и
собирает image по embedded Dockerfile, который:

- использует `alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`;
- скачивает официальные `v1.29.0` musllinux binaries;
- проверяет SHA-256:
  - amd64 `1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b`;
  - arm64 `6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484`;
- копирует project-owned offline rules;
- не содержит time-varying `RUN` steps в final image и запускается numeric
  non-root UID/GID `65532:65532` из pinned Alpine runtime.

Команда `secscan update` строит image локально и сохраняет проверенный immutable
local image ID `sha256:...` в manifest. Build требует сеть; сами scans
работают с `--network none`. Фактический image ID и engine version попадают в
coverage metadata. Opengrep получает отдельный ephemeral `/tmp` tmpfs 256 MiB
с `exec,nosuid,nodev`. Nuitka executable требует исполняемый `/tmp` для распаковки
собственного trusted payload; scanner остаётся non-root, repository и image
read-only, network выключена, а local builds scanned project не разрешены.

Image содержит LGPL-2.1 license и `THIRD_PARTY_NOTICES` с upstream release URL,
version, binary hashes и ссылкой на соответствующий source. Opengrep binary не
модифицируется.

### 12. Rules v1 — узкий собственный набор

Broad Opengrep/Semgrep rule repositories имеют Commons Clause или Semgrep Rules
License и не встраиваются в продукт автоматически. V1 содержит только
оригинальный project-authored high-signal набор под отдельной MIT-лицензией в
`scanner/opengrep/assets/rules/LICENSE`; third-party rule code не копируется:

- Python: dynamic `eval`/`exec`, `subprocess` с `shell=True`, unsafe YAML load,
  без generic weak-hash rules, которые дают ложные positives на checksums;
- TypeScript: dynamic `eval`, interpolated `child_process.exec`, unsafe
  `innerHTML`, disabled TLS verification и weak randomness только для
  token/secret/key/nonce variables.

Rules проходят positive и negative fixtures. Report записывает rule pack
SHA-256 и точное rule count. Coverage честно называется `project-default-v1`;
поддержка внешних rule packs и broad community coverage остаётся отдельным
outcome.

### 13. Opengrep output очищается на adapter boundary

Scanner DTO декодирует только allowlisted JSON fields: check ID, severity,
path, start/end positions и language metadata. Canonical finding получает
статическое project-owned message по rule ID. Source lines, snippets,
metavariable values, raw scanner errors и arbitrary rule messages не переходят
в report или progress. Parse errors называют scanner и field, но не включают
исходный JSON.

### 14. Prepared scanner assets and immutable feeds

`internal/scanner` contains the finite scanner catalog, isolated argv, local
preparation manifest and format adapters. It is not a plugin framework.
`secscan update --scanners ... [path]` resolves pinned upstream images, builds
project-owned images and prepares only feeds required by discovered ecosystems.
A temporary generation is populated first; content hashes and metadata are
published atomically only after every selected preparation succeeds. An old
manifest remains usable after a failed update. Unselected entries are retained.
Concurrent update publication must not lose another completed update.

The default cache is the host user cache under `secscan`; it is outside the
scanned repository. Scan checks required image IDs and feed digests locally,
uses `--pull never --network none`, and never builds or updates assets.
Snapshots expire after five days, including upstream database build age where
available. Scanners receive writable disposable copies when their engines need
write access. Snapshot digest and acquisition time are included in coverage.
OSV ecosystems are an allowlist derived from inputs; no repository content is
sent to the feed server. Missing ecosystems fail coverage.

### 15. Remaining external adapters

Pinned versions: Zizmor 1.30.0, Poutine 1.1.6, Checkov 3.3.16, KICS 2.1.20,
Trivy 0.74.0, Grype 0.118.0, OSV-Scanner 2.5.1, Semgrep 1.176.0,
Bearer 2.1.1, Cppcheck 2.21.1. Pins are recorded in the scanner catalog.
Use the regular KICS 2.1.20 multiarch image; runtime verification showed the
ubi8 variant is amd64-only. Do not misreport the unavailable 2.1.21 image.

JSON adapters decode only documented structured fields; Cppcheck/Bearer can
use SARIF. Result messages and snippets are untrusted and are replaced with
static messages. Paths must resolve inside the staged input tree. Parsing
failure, tool crash, failed files/queries and missing data remain explicit.
Safe flags suppress findings exit codes; operational exits remain failures.
No repository-provided config, custom checks or executable plugins are loaded.

Checkov Terraform includes terraform, terraform_json and terraform_plan;
general Checkov excludes those and API-only SCA/SAST frameworks. Neither
fetches external modules. KICS uses embedded queries and no description fetch.
Zizmor discloses omitted API audits. Applicability is based on Git inventory;
no matching input is skipped. Semgrep reuses embedded MIT Opengrep rules.
Bearer runs only on the container server's amd64 architecture, without emulation.
Its default rules require network at scan time, so update prepares a private
static rule cache from bearer-rules v0.48.4, commit
30a6919acec715bf915ff4704d1b4ffeac998eab (552 rules). The pinned source archive
SHA256 is 790e2a9bdfc26d9447a1f3038c4079c7ed56bb6e61c49a924a96d61b5e5fbfd5.
Cache retains ELv2 license and verifies content identity. Static assets have no
five-day CVE-feed TTL. Scan disables default rules, version checks, domain
resolution, target config/ignore loading and archive extraction, and mounts
only verified external rules. Rule blobs are never embedded in secscan.
The native amd64 acceptance test is explicit; an arm64 skip does not claim
that the amd64 analysis path was runtime-verified on this host.
Bearer 2.1.1 SARIF has no reliable per-file completion evidence. Only validated
finding paths provide positive read evidence; all remaining selected inputs
stay unread. Empty SARIF without positive analysis evidence fails as coverage
unconfirmed, rather than producing a clean success. Partial findings remain
useful and retain the explicit coverage limitation.
Semgrep and Bearer images are pulled from upstream
at runtime preparation and are not redistributed by this project. Semgrep's
current image labels reference proprietary source; do not label it LGPL-only.
Cppcheck is built from exact source with GPL source/license/build recipe.

### 16. Dependency identities, Gradle and OCI

Canonical findings gain optional package identity, advisory aliases and
locations. Dedup uses package ecosystem/name/version (canonical PURL when
available) plus connected advisory aliases. It merges transitively and sorts
sources, advisories and locations deterministically. Code findings from the
shared Semgrep/Opengrep pack merge by rule and location.

Gradle catalogs use a real TOML parser if required by the documented grammar;
script extraction is deliberately limited to literal coordinates. Dynamic
expressions, unresolved version references and plugins are disclosed as unread.
No wrapper, build or project code executes. Extracted Maven inventory is passed
to the same offline advisory stage. refresh-versions reads existing metadata
only and labels its result as configuration analysis.

OCI discovery reads literal FROM/image fields from Dockerfiles, Kubernetes and
Compose. No target registry access occurs without --scan-images. With the flag,
host runtime records local ownership, resolves/pulls and exports an archive.
Trivy and Grype consume this archive without a socket; finally removes only
images newly loaded by this run. Preserve pre-existing images on every exit,
including cancellation. Scanner metadata records the host-network capability.

### 17. Full-roster runtime integration

A real 18-job render produced 27 lines. TTY rendering therefore budgets recent
log lines from the actual terminal height while preserving every scanner row.
When even scanner rows cannot fit, it restores the cursor and switches to the
existing plain reporter. JSON stdout is unchanged. Terminal resize and empty
state are covered by focused rendering checks and a PTY run.

A real canceled Docker client left its started container running. The common
runtime assigns an unpredictable owned container name before every scanner
run and removes that container with a separate bounded cleanup context after
cancellation. It does not remove arbitrary user containers. All run/output
entrypoints share this cleanup; tests verify the daemon state, not only client
exit. OCI target-image ownership remains a separate guard in the image adapter.
A failed job retains its supplied canonical evidence and completed findings;
orchestration adds a static error finding and forces its failed status. The CLI
serializes an available attempted-scan report even on failure, with exit1 when
no scanner succeeded. Errors before a report exists still produce diagnostics
only. This preserves OCI image digests, granted capabilities and cleanup status.

### 18. Delivery boundaries

Beads owns six outcomes: preparation, CI, IaC, dependencies, additional SAST,
and static Gradle/OCI. Every outcome depends on the proven Gitleaks skeleton;
adapters also depend on preparation and Gradle/OCI depends on dependencies.
Each outcome carries baseline, target and final trace evidence and independent
review before closure. Revert its Conventional Commits to roll back; cached
snapshots are additive and prior manifests survive failed updates. Existing
Gitleaks/Opengrep users run secscan update once after this compatibility change.

## Risks / Trade-offs

- Поддержка Docker и Podman может разойтись. Общий код ограничивается
  совместимым argv; runtime-specific различия добавляются только по тесту.
- Gitleaks JSON может меняться. Scanner DTO остаётся внутренним, malformed input
  закрывается ошибкой.
- Trace manifest добавляет ручную связь. Пилот измеряет стоимость её поддержки;
  формат не расширяется до второго применения.
- Запуск repository-defined commands обладает полномочиями пользователя.
  `tracecheck --run` применяется только к reviewed manifest текущего проекта.
- Отсутствие container runtime блокирует readiness walking skeleton, даже если
  unit tests зелёные.

## Least Confident Decisions

- Совместимость одного argv для Docker и Podman должна быть подтверждена
  реальными acceptance runs.
- Минимальных полей schema v1 может не хватить второму scanner adapter.
  Расширять schema разрешено добавочно; менять смысл существующих полей нельзя.
- Project-owned rules v1 намеренно уже broad commercial/community packs;
  report обязан раскрывать этот ceiling.

## Rollback

Walking skeleton не изменяет внешние системы. Rollback состоит в revert
гранулированных design, verifier и product commits. Scanner containers
запускаются с `--rm`; temporary directory удаляется после завершения.

## Verification Strategy

- `openspec validate --all --strict`
- `opsx-stale check openspec/changes/build-secscan`
- focused Go tests для CLI, parser, redaction, argv и tracecheck
- golden tests для TTY/plain renderer без wall-clock sleeps
- positive/negative Python и TypeScript rule fixtures
- `gofmt -d .`
- `go vet ./...`
- `go test ./...`
- real Docker и Podman acceptance по доступности каждого runtime
- real Opengrep acceptance для Python и TypeScript fixtures
- `tracecheck --phase final --run` против полного changed-file set
- независимый Go/security review записывается в Beads отдельно от command
  evidence

## Open-source release design

Use public sagolubev/secscan and canonical Go module github.com/sagolubev/secscan.
MIT covers project-owned code; copied skills, Go dependencies and engine recipes
retain their original notices. Embed the project's license and dependency
notices in the executable and expose --licenses; --version identifies tag builds.
Scanner payloads and databases are never GitHub Release assets.

GitHub Actions uses pinned action commits, read-only test jobs and a separate
contents:write publish job. Pull requests use pull_request, never
pull_request_target. Format/vet/module/tests/race run on Linux and macOS;
Linux jobs exercise actual isolated container engines. Four CGO-disabled,
trimpath binaries target linux/darwin × amd64/arm64. Native OS jobs smoke-test
the corresponding executable. Tag release reuses the checks, downloads their
build artifacts and publishes the four raw binaries plus SHA256SUMS.

Add a validation-only tracecheck mode for CI. It reuses existing scenario/scope/
Beads checks, adds strict validation of the existing .stale.json hashes, and
emits validation data only. Existing baseline/target/final --run semantics stay
intact. CI installs pinned br and OpenSpec tooling; no private workstation
scripts or credentials are required. Native scanner acceptance failures block
release; unsupported native platforms are disclosed, not reported as verified.

Record the GRACE evaluation in docs/grace-pilot.md. Use Git, br and verifier
source/tests as evidence; distinguish review-discovered bugs from verifier
failures. No comparative time/token savings are assumed. Local checks precede
publication; actual hosted workflow and release assets establish readiness.
Rollback is additive corrective commits/releases; do not rewrite the existing
project history or replace a released asset silently.

### Hosted acceptance correction: private Opengrep build contexts

The first public Linux amd64 CI run exposed concurrent package preparation
mutating a shared Opengrep rootfs directory. Read-only license replacement
failed; a build could also observe a tree being reset by another caller.
Keep verified downloads shared, but materialize a unique build context per
EnsureImage call and remove it only after that build completes. Preserve
normalized bytes/modes/timestamps, image pins and parallel CI. Regression
coverage prepares multiple contexts concurrently and checks their contents;
real CLI/Opengrep/code acceptance still runs in parallel packages.

## Trivy reports for Dependency-Track and SonarQube

Keep the existing Trivy filesystem scan with `--list-all-pkgs`, pinned image,
read-only staged inputs and offline database. The adapter creates two sanitized
payloads from that one result only when export is requested. Never build an
SBOM from vulnerability findings: clean packages must survive. Only allowlisted
package identities, known dependency edges, advisory IDs, severity and validated
manifest paths cross the adapter boundary. Raw messages, URLs, descriptions,
license text and scanner properties are excluded.

Use small standard-library JSON encoders for CycloneDX 1.6 and SonarQube's
rules/issues format. Native Trivy0.74 conversion emits CycloneDX1.7 and has no
version selector, requiring Dependency-Track5.1+; a second conversion container
and schema downgrader are unnecessary. The chosen output works with
Dependency-Track4.12+. BOM references are deterministic, duplicate identities
merge, dangling/ambiguous relationships are rejected, and unknown dependency
relationships remain unknown. The SBOM contains inventory, not Trivy BOV data.

SonarQube Server10.3+ reads Generic Issues via sonar.externalIssuesReportPaths.
Use file-level primaryLocation without invented lines. Export only Trivy's own
advisories/severities, before cross-scanner merging. Rules carry Standard
severity/type and SECURITY impacts for MQR. Critical/high map to HIGH impact,
medium to MEDIUM, low/unknown to LOW with unknown explicitly named. Standard
mapping is BLOCKER/CRITICAL/MAJOR/MINOR/INFO. A stable rule key includes severity
to preserve cases where the same advisory has different severity per package.
Explicit Standard rule fields are verified on Server2025.1+. Older importers,
including10.3/10.7, derive Standard severity from impacts and therefore merge
critical/high and low/unknown. Document that display limitation while retaining
current-format import compatibility. All issues reference an emitted rule.
No vulnerabilities produces rules:[] and
issues:[], not null. Sonar file indexing/exclusions are an import prerequisite.

CLI `--trivy-reports DIR` requires trivy in the selection and is unavailable
for update. Keep the normal JSON stdout and progress stderr contracts. A
requested export fails with exit1 for Trivy failed/skipped/incomplete inventory,
even when another scanner succeeded. Generated payloads remain internal fields
excluded from JSON. Reserve a new directory outside the resolved worktree after
checks; refuse existing files/directories/symlinks, create private files and
remove only newly owned output on write failure. Check cancellation before
publication. No remote calls, server credentials or automatic uploads are added.

One Beads outcome proves the full path through real Trivy into both files.
Tests cover clean/vulnerable packages, deterministic graph references, hostile
scanner fields/paths, repeated IDs, mixed severities, empty findings, incomplete
coverage, output conflicts and unchanged stdout. Validate a generated SBOM
against the official CycloneDX1.6 schema and compare Sonar output with the
published importer contract. Local format validation does not claim successful
import into a user's server. Preserve all existing broad/runtime gates and
independent security review. Rollback: omit the flag or revert additive commits;
existing user reports and source files remain untouched.

## Portable binary installer

Add root install.sh using POSIX sh, curl and SHA256 tools already available on
Linux/macOS. Reuse the repository's existing HTTPS download and checksum pattern;
local GitHub-card search confirmed the common installer approach in GoBackup and
Toad, but their product-specific installers are not dependencies. Use one
stable-tag resolution through GitHub releases/latest HTTPS redirect, then fetch
both artifacts from that exact tag. No API token, JSON parser or compiler is
required. Version input must match vMAJOR.MINOR.PATCH; URL origin/repository are
fixed. Reject invalid latest redirect responses.

Read --version and --dir, detect uname OS/architecture, and prefer sha256sum
with shasum -a256 fallback. A private mktemp download directory and traps limit
cleanup to owned files. Reject missing, malformed or duplicate checksum entries.
Create a temporary file inside the destination directory only after digest
verification, set executable mode, and verify --version before rename to secscan.
Reject directory/symlink destinations, preserve previous executable on failure,
and clean both staging locations. Default directory is ~/.local/bin; print a
PATH hint when necessary without editing profiles. Do not use sudo, change
permissions on existing directories or install Git/container runtimes.

Tests use Python unittest from the standard library and subprocess execution of
the actual script through stdin. Fake curl/uname isolate downloads and platform
selection; real shell/filesystem/SHA256 tools exercise installation and failure
behavior. Synthetic executable payloads prove that an invalid digest never runs.
Cover all four targets, latest tag pinning, specified versions, spaces in paths,
checksum/download errors, failed executable validation, upgrades and conflicting
destinations. Run on Linux/macOS in existing CI checks. Finally install the real
released binary into a temporary directory and inspect --version/--licenses.
An independent security review covers the network-to-executable boundary.
Rollback is removal of the installer/docs commit; existing release assets and
application behavior are unchanged.

## Coverage inventory and source navigation

Git remains the enumeration authority. Query tracked, untracked nonignored and
ignored paths separately with NUL framing and fsmonitor disabled; deduplicate
paths and never follow symlinks while inspecting. Each entry is either eligible
regular input, ignored regular input, or an explicit omission (symlink, missing,
non-regular, control file). Keep selected paths internally for staging. Publish
file/byte counts per bucket and immediate-parent directory; counts are not
recursive, so directory rows can be summed. Preserve legacy ignored counters.
Classify finite known source languages and dependency manifests; disclose
unclassified eligible files separately. After scanner completion, report code
and dependency gaps using scanner selection/status/read evidence. Secret scans
do not count as SAST or dependency analysis. Scanner-specific coverage remains
separate from filesystem inventory.

Stage Gitleaks inputs through discovery.Stage, like language adapters, rather
than mounting the original tree. Empty eligible input means skipped without a
runtime requirement. Keep its repository-level coverage unit; do not fabricate
per-file positive read evidence. This intentionally fixes ignored files being
outside the previously reported exclusion boundary. Test a real synthetic
secret in ignored and selected locations; only selected input may appear.

Use upstream START_MODULE_CONTRACT/START_MODULE_MAP and optional START_CONTRACT
markers for key changed Go files. Runtime maps list exported symbols in that
file; SCRIPT/LOCALS maps identify CLI boundaries. PURPOSE/SCOPE describe only
useful invariants; LINKS point to existing spec anchors and concrete test names.
The concise protocol lives in docs/code-navigation.md and is referenced by
AGENTS.md. This is source navigation, not full upstream graph enforcement.

## Product baseline comparison

Use a small internal/baseline module over the canonical report types. Snapshot
JSON has its own schema version and explicit fingerprint algorithm identifier,
and stores unfiltered normalized findings only. Relative finding paths make it
portable between checkouts. Decode bounded data strictly; reject incompatible
versions/unknown schema, malformed identities and noncanonical locations without
echoing untrusted content. Never copy old messages into new output.

For code/configuration, match kind/rule/language/origin/image and canonical
source identity; compare locations. For dependencies, require equal package
identity/version/qualifiers/image and overlapping advisory IDs before treating
findings as the same issue. Newly unrelated advisories are new issues. Merge
old matching locations/aliases for comparison. Show new locations, new advisory
IDs and severity increases. When both location and advisory dimensions grow,
retain their union without inventing or dropping combinations: new advisories
at current locations plus known advisories at new locations. Secrets/errors
always remain visible. Keep counters for original findings and explicit output
fragment counts. No resolved-finding claim is inferred from an incomplete scan.

CLI applies baselines after scanning; Trivy exports use the original unfiltered
result. --write-baseline and --baseline are mutually exclusive, unavailable for
update and validate paths before execution. The write command creates a new
snapshot only; existing files are preserved. Baseline data is encoded before
publication, with atomic no-clobber publication in the chosen filesystem. Read
and write paths inside the worktree are explicit excluded control files, passed
as scan options and reflected in traversal omissions. A failed scan cannot
produce a successful baseline write; partial coverage is retained in the report
and never becomes proof of absence. Exemption and new/expanded behavior get
focused tests plus a CLI acceptance fixture. Comparison never mutates input
findings or stored snapshots. Existing JSON v1 changes are additive.

## Offline HTML and complete SARIF

Add --html FILE and --sarif FILE without changing JSON stdout. Both flags may
be combined with baseline comparison. HTML renders the visible result; SARIF
always receives the complete unfiltered scan. Coverage, scanner limitations,
inventory and operational failures remain visible even with zero findings.
An attempted failed scan may still produce these reports, with exit1 preserved.
Update rejects the flags. Invalid or existing destinations fail before scanning.
All output flags share a collision check. Group destinations by opened-parent
identity, then test their names in a private sibling directory so native case
and Unicode aliases are rejected without creating any requested output. Remove
the owned probe before scanner discovery; no new normalization library is needed.

Use html/template and encoding/json from the standard library. The reviewed
local Trivy and SEC-AF cards describe broader scanner platforms, not a suitable
canonical-report library. Reuse this codebase's normalized Report instead of
adding their runtimes. A static HTML document uses semantic headings/tables,
native details, embedded CSS and CSP; no scripts, remote assets, source snippets
or executable links. Escape all data through templates. Keep complete findings
and evidence, using native browser search and print rather than a JS application.

SARIF 2.1.0 has one secscan run, deterministically ordered rules/results,
repository-relative URI-encoded locations and existing stable fingerprints.
Keep canonical package/advisory/source/image fields as result properties and
full coverage as run properties. Emit explicit invocation notifications for
failed/skipped/incomplete analysis. Omit unknown regions rather than inventing
lines; reject invalid canonical paths or line ranges. Validate a generated file
against the OASIS 2.1.0 schema, in addition to focused mapping tests.

Extract the existing baseline file destination into one shared concrete helper:
pin the parent before scanning; create a private temporary file under os.Root;
sync complete bytes and publish with Linkat without replacing an existing name.
Baseline and report files use the same cancellation/cleanup boundary. Explicit
in-worktree outputs are excluded control paths before staging. Rendering happens
before publication; errors preserve JSON stdout and existing files. Multiple
outputs are independent complete files, not a cross-file transaction.

The report outcome owns internal/report renderers, CLI wiring/publication,
README examples and trace links. It proves a real Python scan into JSON, HTML
and schema-valid SARIF, including baseline-filtered HTML with full SARIF, hostile
text, failed coverage, parent replacement and no-clobber behavior. Rollback is
omitting the additive flags or reverting the outcome commits. Standard feature
artifacts and Comprehensive security/verification gates apply.

## Strict project filters

Read optional .secscan.toml from the Git root before scanning. --config FILE
selects an explicit file; --no-config ignores project policy. These flags are
mutually exclusive and unavailable for update. --min-severity overrides the
configured floor. Missing default config is allowed; an explicit missing file,
symlink, non-regular file, oversized file or invalid TOML fails before scan.
Only an existing selected control file is excluded from discovery. Use the
installed go-toml/v2 strict decoder and bounded 1 MiB reads, with static errors
that never echo configuration contents. No plugins, includes or code execution.

Config schema version=1 has optional min_severity, test_paths and suppressions.
Each suppression requires a unique ASCII id, a nonempty reason and at least one
selector: kind, rule, fingerprint, path or advisory. Selectors are intersected;
rule/advisory/fingerprint are exact. Paths are repository-relative exact names,
Go path.Match globs (no recursive **), or a trailing-slash directory prefix.
Reject absolute/traversing/malformed patterns, unknown keys, invalid kinds or
severity, duplicate ids and more than 256 rules. A reason is required for review
but is not copied into scan output. Test-data paths use the same path grammar.
Unknown finding severity remains visible at any configured floor.

Maintain full normalized findings independently of the visible view. Process
native scanner waivers at the existing scanner boundary; then project rules in
file order, baseline, severity floor, and explicit test-data paths. Native inline
waivers have no retrospective counts because adapters do not receive those
findings. Never hide secret/error findings through any project filter. Snapshot,
SARIF and Trivy exports always consume the full model.

Partial dependency suppression subtracts selected advisory/location combinations:
retain all advisories at unselected places and remaining advisories at selected
places. Keep fragments separate and preserve the original fingerprint. Add a
baseline entrypoint for already-normalized fragments that validates and clones
them without re-merging or recomputing identity. Baseline-only behavior remains
unchanged. With project splitting, baseline counters describe the fragments
entering that stage; the filtering summary records original finding counts and
final output fragments separately. JSON/HTML must not normalize these fragments
back together, and SARIF rejects a filtered model passed by mistake.

Record each stage's removed findings, places, advisories and occurrences. Counts
are differences of sets keyed by original fingerprint; an occurrence is one
finding/place/advisory combination (one place for code findings). A place or
advisory counts as removed only when no surviving fragment contains it. Thus
overlapping rules cannot count an element twice; partial pair removal remains
visible even when neither whole place nor advisory disappears. Retain coverage
and inventory independently of filtering.

The outcome owns internal/filter, additive report accounting, the baseline
fragment entrypoint and CLI config/pipeline. Verify strict/hostile configs,
overlapping and partial rules, exemptions, baseline ordering, unchanged full
exports and input immutability through focused tests plus a real CLI fixture.
Rollback: --no-config/remove optional flags or revert the outcome commits.

## Explicit scan scopes

Add repeatable --scope PATH, at most 16 arguments, relative to the resolved Git
root. Normalize ./ and duplicate/overlapping selections. Require Git inventory
spelling: a filesystem case alias with no matching Git path is an error, never
an empty successful scan. Reject empty, absolute, traversing, backslash, symlink,
non-regular, missing and zero-eligible-file selections. A scope uses only safe
nonignored regular inputs after control exclusions. Update, --baseline and
--write-baseline reject scopes with usage exit2.

Keep full and narrowed inventories. Narrow only Gitleaks, project Python and
TypeScript SAST, Semgrep's same local rule pack, and Zizmor. Other personas keep
the full repository candidates: Bearer, Cppcheck, IaC, Poutine, dependencies,
Gradle and OCI may require wider context. Their findings stay attached to actual
paths, including paths outside the requested scope. No result filter pretends
they scanned less. One finite scanner-input mapping serves execution selection
and scope metadata to prevent the two descriptions drifting apart.

Add optional Report.Scope with paths and selectedFiles, and Scanner.Scope with
mode (files or repository) and candidateFiles. Counts are candidate inputs, not
proof of reads. The existing traversal inventory still describes the complete
Git worktree. Coverage gaps use scoped code inputs unless a whole-repository
code scanner is selected, and complete dependency candidates when a dependency
or Gradle scanner uses them. HTML and SARIF disclose the same scope metadata.
Unscoped behavior and JSON remain compatible.

discovery.SelectScopes(root, fullInventory, scopes) returns a narrowed inventory
and sorted unique requested paths. It filters all candidate slices without
mutating the full inventory and preserves its traversal metadata. CLI selects
the appropriate full/narrowed candidates per persona, including applicability
and runtime preparation; an out-of-scope file must not trigger a narrowed job.

Verify file/directory unions, controls, ignored/deleted paths, symlinks, argument
limits and conflicts, preservation of full metadata, and no input mutation.
A real two-directory Python fixture proves only the selected source is analysed;
a simultaneous refresh-versions fixture proves a whole-repository persona keeps
its outside-scope finding and scope mode. Rollback: omit --scope or revert the
additive outcome. Shared report/filter/snapshot behavior remains under regression
tests and independent review.

## GRACE assurance after the audit

The correction has three bounded outcomes: Git/manifest identity, portable phase
evidence, and code-navigation/CI enforcement. Preserve the existing OpenSpec and
Beads authorities. Use the installed br comment API: a probe confirmed comment
text survives JSONL export and import into a new database. No second evidence
database or .grace projection is needed. Profile: bugfix for snapshot binding,
feature for evidence/navigation guards; Comprehensive verification, including
negative fixtures and independent review. Each outcome proves its real CLI seam.

### Git and manifest binding

Enumerate the union of baseline-to-HEAD, baseline-to-index and baseline-to-working
tree diffs plus nonignored untracked files. Deduplicate identical changes and
preserve all rename source/destination paths. Resolve the baseline as an immutable
full commit ID, reject unresolved index conflicts, and disable external Git diff
helpers. Identity v2 includes distinct index and worktree content/Git modes for
every relevant path. It must detect staged-only bytes, mode changes, deletions
and renames, and remain stable when matching staged bytes are committed. Only
.beads/issues.jsonl may be an evidence sink. Secret-path guards remain in force.

The loaded manifest must be a bounded regular JSON file inside the repository;
bind its normalized path and exact byte digest into validation and evidence.
Reject trailing/ambiguous JSON, escaping paths and unsupported sink exemptions.
Reload it after checks so an edited alternate manifest invalidates the result.
Baseline refuses any implementation change since its anchor. Target/final require
index/worktree agreement outside the evidence sink; stage reviewed files first.
Validation-only reports state but never implies executed tests. Verify deferred
Beads IDs and parent/status, safe component references and recognizable test
files/optional Go test symbols; semantic test sufficiency remains independent review.

Emit schema-v2 evidence with identity algorithm, manifest path/digest, UTC start
and finish, explicit check status and a deterministic record digest. This is an
integrity reference, not a signature or proof that the operator is trustworthy.
The first verifier correction uses its already captured v1 baseline honestly;
it is archived as bootstrap legacy, not converted into a fictitious v2 chain.

### Portable phase chain

Append complete evidence as machine-tagged Beads comments through br. Records are
content addressed and never replace earlier attempts. Target requires a successful
baseline with matching outcome, anchor, authority and manifest; final requires a
successful current target and links its digest. Baseline has no parent and proves
preimplementation state. The manifest/check plan must remain fixed across a chain;
unexpected scope or command changes require a new explicitly planned outcome.
--verify-evidence loads the chain from Beads, checks digest links, phase order,
timestamps, exact checks and current state without rerunning scanners. A clean
clone must be able to verify it. Use this check before br close and in CI.

Record passed/failed command states, bounded output byte counts/digests, and
passed/failed/skipped counts for declared go-test-json checks. Do not commit raw
stdout/stderr, config contents or secret-bearing snippets. A native acceptance
check must have passed tests; an all-skipped run cannot satisfy it. Baseline checks
for the first chain rollout stay compatible with the newly bootstrapped v2 runner.
Preserve old v1 and unchained bootstrap evidence under a distinct legacy tag,
with import provenance and limitations. Legacy records cannot satisfy new phase
gates; .17 remains explicitly marked as captured after its regression edit.

### Navigation and rollout

Use Go AST parsing to check existing marked files and require contract/maps for
new or changed Go source in cmd/ and internal/ for the selected outcome. Validate
marker pairs, ROLE/MAP_MODE, mapped symbols/exports, dependency/link paths and Go
symbol anchors. Fill audited missing metadata; do not require blanket decoration
of unchanged legacy code. Keep checks inside tracecheck, not a parallel linter.
Update AGENTS/README/development docs and CI to use the new chain and markup gates.
Historical pilot documents retain their dated claims with a current-status note.

Regression fixtures cover staged-only/out-of-scope changes, rename/mode/deletion,
manifest substitution and mutation, late baseline, missing/stale/tampered chains,
Beads round-trip persistence, fake task/test references, missing/stale code maps
and all-skipped tests. Existing source and container gates remain. Rollback is an
explicit corrective commit; never silently weaken the guards or rewrite evidence.


## Private offline rule packs

Feature profile, Standard artifacts, Comprehensive verification. Outcome .23
is one vertical skeleton on the existing prepared engine/container boundary.
Reuse installed go-toml/v2 and yaml/v3; the local Opengrep card and pinned engine
help confirm local YAML configs and --no-rewrite-rule-ids. Do not use --validate,
which may fetch registry lint rules. Import checks the safe bundle grammar;
the chosen engine checks its full rule DSL during an ordinary offline scan.

Add `secscan rules import DIR` and `secscan rules show ID`, both returning JSON.
DIR/rules.toml has version=1, source, license, license_file and files; optional
revision records a full commit SHA. Source is `local` or HTTPS without credentials,
query or fragment. The license identifier/expression is a declaration, not legal
approval. Retain its nonempty UTF-8 license file in the private cache; no rule
corpus is embedded in binaries or automatically downloaded/redistributed.

The manifest explicitly selects at most 256 relative YAML files. Reject escaping
paths, symlinks/nonregular inputs, duplicate fields/files/rule IDs, aliases,
merge keys, nonstandard tags, executable validators and remote includes. Bound
manifest/license to 64 KiB each, a rule file to 2 MiB, the canonical bundle to
16 MiB and total rules to 4096. Rules require bounded identifiers, supported
source-language tags and ERROR/WARNING/INFO severity. Reserve secscan.* IDs for
built-ins. Semantic DSL errors remain operational failures, never clean scans.

A small internal/rules package stores one canonical JSON bundle per SHA-256 ID
under the existing user cache's prepared/rule-packs directory. Sort file entries;
identity covers version, provenance, license bytes and exact YAML bytes. The
payload contains no acquisition time or absolute input path. Load verifies ID,
canonical encoding and the same grammar before returning an immutable Pack.
Use private temporary files and no-clobber publication; existing IDs are verified,
not overwritten. Snapshot validated bytes in memory, then materialize only YAML
into owned temporary scanner directories. This avoids mutable cache mounts and
keeps credentials/license files outside scanner inputs.

`--rule-pack ID` is an explicit scan option, not repository configuration. It
requires Semgrep, python-sast or typescript-sast in the selection, rejects update
and malformed IDs, and loads the bundle before scanning. Default execution is
unchanged. Semgrep adds applicable known source inputs from discovery; Python
and TypeScript jobs use their existing language inputs and matching rules only.
One input helper serves execution, runtime need, scopes and coverage accounting.
Reject unsupported language tags rather than claiming that ignored rules ran.

Retain built-in rules and their IDs/fingerprints. Disable engine ID rewriting;
recognize custom output IDs only from the loaded pack. Canonical custom rule IDs
include the full pack ID to separate versions. Emit static `custom rule matched`
messages, validated paths/lines and declared severity; discard arbitrary engine
messages, snippets, metavariables and raw errors. Report custom pack provenance
and counts separately, plus a deterministic effective rule-pack digest. Shared
Semgrep/Opengrep findings for the same pack/rule/location can still merge.

Verify CLI usage/rollback, deterministic reimport, tampering, hostile files/YAML,
failed publication, input immutability, scope routing and unchanged built-ins.
Real acceptance imports synthetic rules, runs prepared Semgrep and Opengrep with
network disabled, and checks custom findings, positive reads and redaction.
Existing full source/native checks, GRACE maps and independent security review
remain required. Rollback selects an earlier ID, omits the flag or reverts the
additive commit; no previous cache entry or user report is removed.

Least confident: third-party rule DSL support differs between the two pinned
engines. Import does not promise that every rule is compatible with both;
engine parse failures are explicit. A mismatch must not be fixed by skipping
invalid rules or weakening read-evidence checks.
