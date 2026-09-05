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
- Зафиксировать минимальный schema-v1 JSON contract.
- Удалить secret values и source snippets до выхода из adapter boundary.
- Проверить security options container invocation без shell interpolation.
- Связать требования с components и tests.
- Выдавать `baseline`, `target` и `final` evidence, привязанное к Git-состоянию.
- Проверять полный changed-file set относительно declared scope.

**Non-Goals:**

- Остальные scanner personas кроме Gitleaks, Python SAST и TypeScript SAST.
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

Image pull выполняет runtime до запуска scanner container, если image
отсутствует. Фактически использованный digest записывается в coverage metadata.

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

У Opengrep нет подтверждённого официального container image. Репозиторий
содержит multi-stage `scanner/opengrep/Dockerfile`, который:

- использует `alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`;
- скачивает официальные `v1.29.0` musllinux binaries;
- проверяет SHA-256:
  - amd64 `1b474bf207905a3cffe4e915fe36895835bc89de2620cb2ffd88ca512d9ea31b`;
  - arm64 `6cccb7466a98608e308204e17b259f4ca3a9028c6eb71e6b07ea21b89026c484`;
- копирует project-owned offline rules;
- запускается как non-root из pinned Alpine runtime.

Первый scan строит image локально при его отсутствии и затем запускает scanner
по immutable local image ID `sha256:...`. Build требует сеть; сами scans
работают с `--network none`. Фактический image ID и engine version попадают в
coverage metadata.

Image содержит LGPL-2.1 license и `THIRD_PARTY_NOTICES` с upstream release URL,
version, binary hashes и ссылкой на соответствующий source. Opengrep binary не
модифицируется.

### 12. Rules v1 — узкий собственный набор

Broad Opengrep/Semgrep rule repositories имеют Commons Clause или Semgrep Rules
License и не встраиваются в продукт автоматически. V1 содержит только
оригинальный project-authored high-signal набор под отдельной MIT-лицензией в
`scanner/opengrep/rules/LICENSE`; third-party rule code не копируется:

- Python: dynamic `eval`/`exec`, `subprocess` с `shell=True`, unsafe YAML load,
  weak hash for security-sensitive use;
- TypeScript: dynamic `eval`, interpolated `child_process.exec`, unsafe
  `innerHTML`, weak randomness for secret/token generation.

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
