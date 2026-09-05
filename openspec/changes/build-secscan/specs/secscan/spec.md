## ADDED Requirements

### Requirement: CLI contract

Система SHALL предоставлять команду `secscan [flags] [path]`, где `path` по умолчанию равен текущему каталогу и разрешается в корень содержащего его Git worktree.

#### Scenario: Machine-readable stdout
- **WHEN** пользователь запускает scan без файлового output override
- **THEN** stdout содержит ровно один JSON-документ schema v1
- **AND** progress и diagnostics направляются только в stderr

#### Scenario: Exit status
- **WHEN** scan завершился и хотя бы один scanner успешно выполнил анализ
- **THEN** процесс завершается с кодом `0` независимо от количества findings
- **WHEN** scan не состоялся или все scanners завершились ошибкой
- **THEN** процесс завершается с кодом `1`
- **WHEN** аргументы некорректны
- **THEN** процесс завершается с кодом `2`

### Requirement: Container runtime

Система SHALL запускать scanners через Docker или Podman без установки scanner runtimes на host.

#### Scenario: Safe repository mount
- **WHEN** scanner запускается
- **THEN** Git worktree монтируется read-only
- **AND** container получает `no-new-privileges`
- **AND** scanner не получает Docker socket
- **AND** writable cache и temporary directories ограничены отдельными mounts

#### Scenario: Rootless runtime
- **WHEN** daemon использует user namespace remapping или rootless mode
- **THEN** созданные cache artifacts остаются доступны текущему host user

#### Scenario: Runtime unavailable
- **WHEN** ни Docker, ни Podman daemon недоступны
- **THEN** secscan объясняет, какой runtime был обнаружен и почему соединение не удалось
- **AND** не создаёт scan report

### Requirement: Scanner orchestration

Система SHALL поддерживать personas `gitleaks`, `python-sast`,
`typescript-sast`, `semgrep`, `trivy`, `grype`, `checkov`,
`checkov-terraform`, `osv-scanner`, `zizmor`, `bearer`, `cppcheck`,
`gradle-catalog`, `gradle-scripts`, `refresh-versions`, `kics`, `poutine` и
`oci-images`.

#### Scenario: Parallel execution
- **WHEN** несколько применимых scanners выбраны
- **THEN** они выполняются параллельно с ограниченной concurrency
- **AND** timeout и cancellation применяются независимо к каждому scanner

#### Scenario: Partial failure
- **WHEN** один scanner завершается ошибкой, но другой scanner успешен
- **THEN** успешные результаты сохраняются
- **AND** failed scanner присутствует в coverage metadata и error finding

#### Scenario: Scanner selection
- **WHEN** пользователь передаёт `--scanners`
- **THEN** запускаются только перечисленные personas
- **AND** `--scanners all` не включает `oci-images` без отдельного `--scan-images`

### Requirement: Language SAST

Система SHALL запускать отдельные `python-sast` и `typescript-sast` jobs через
один pinned Opengrep engine и project-owned offline rule pack.

#### Scenario: Python files
- **WHEN** Git worktree содержит tracked или untracked nonignored файлы `.py` или `.pyi`
- **THEN** `python-sast` сканирует только эти файлы Python rule pack
- **AND** findings получают language `python` и source scanner `opengrep`

#### Scenario: TypeScript files
- **WHEN** Git worktree содержит tracked или untracked nonignored файлы `.ts`, `.tsx`, `.mts` или `.cts`
- **THEN** `typescript-sast` сканирует только эти файлы TypeScript rule pack
- **AND** findings получают language `typescript` и source scanner `opengrep`

#### Scenario: No matching files
- **WHEN** для language job нет подходящих tracked или untracked nonignored files
- **THEN** scanner получает status `skipped`
- **AND** coverage сообщает `read=0`, `failed=0`, `unit=files`

#### Scenario: Honest rule coverage
- **WHEN** language SAST завершается
- **THEN** report содержит engine version, immutable engine image ID, rule pack digest и фактическое rule count
- **AND** report не заявляет анализ классов уязвимостей, отсутствующих в project-owned rules

#### Scenario: Scanner output isolation
- **WHEN** Opengrep возвращает finding
- **THEN** canonical report содержит только allowlisted rule, severity, language и location fields
- **AND** source snippets, metavariable values и scanner diagnostics не попадают в JSON, progress или error messages

### Requirement: Progress presentation

Система SHALL показывать scanner progress в stderr без изменения JSON stdout.

#### Scenario: Interactive dashboard
- **WHEN** stderr является TTY, `TERM` не равен `dumb` и progress mode равен `auto` или `tty`
- **THEN** secscan перерисовывает фиксированный dashboard со строкой на каждый scanner
- **AND** строка показывает текущую stage, elapsed-time bar, findings count и итоговый status
- **AND** завершение или ошибка восстанавливают cursor и оставляют финальный dashboard видимым

#### Scenario: Plain progress
- **WHEN** stderr не является TTY, `TERM=dumb` или progress mode равен `plain`
- **THEN** secscan выводит стабильные построчные events без ANSI animation
- **AND** каждое событие содержит scanner, stage и elapsed duration

#### Scenario: Color disabled
- **WHEN** `NO_COLOR` задан
- **THEN** выбранный dashboard или plain mode сохраняется
- **AND** ANSI color sequences не выводятся

#### Scenario: Progress disabled
- **WHEN** progress mode равен `off`
- **THEN** scanner progress не выводится
- **AND** diagnostics ошибок по-прежнему направляются в stderr

#### Scenario: Progress mode validation
- **WHEN** пользователь передаёт неизвестное значение `--progress`
- **THEN** команда завершается с usage exit code `2`

### Requirement: Canonical finding model

Система SHALL преобразовывать scanner-specific outputs в versioned schema v1 с kinds `code`, `dependency`, `secret`, `configuration` и `error`.

#### Scenario: Deterministic result
- **WHEN** одинаковые scanner outputs нормализуются повторно
- **THEN** JSON bytes, ordering и fingerprints совпадают

#### Scenario: Cross-scanner dependency deduplication
- **WHEN** Trivy, Grype и OSV сообщают об одной package vulnerability
- **THEN** report содержит одну finding с объединёнными advisory IDs и списком source scanners

#### Scenario: Secret redaction
- **WHEN** scanner сообщает secret
- **THEN** report не содержит secret value или source snippet

#### Scenario: Finding origin
- **WHEN** scanner сообщает finding из working tree или Git history
- **THEN** finding явно указывает соответствующий origin

### Requirement: Honest coverage

Система SHALL отличать отсутствие findings от отсутствия анализа.

#### Scenario: Coverage envelope
- **WHEN** scan завершается
- **THEN** report перечисляет successful, failed и skipped scanners
- **AND** scanner-specific coverage содержит измеряемые `read`, `failed` и `unit`

#### Scenario: Unsupported inputs
- **WHEN** repository содержит dependency manifests или source formats без подходящего scanner
- **THEN** report перечисляет их как unread или unchecked

#### Scenario: Traversal disclosure
- **WHEN** ignored или untracked directories исключены из обхода
- **THEN** report сообщает эти exclusions и фактические file/byte counts

### Requirement: Filtering and suppressions

Система SHALL применять исключения в порядке: native scanner waivers, project suppressions, baseline, severity floor, test-data policy.

#### Scenario: Exempt findings
- **WHEN** finding имеет kind `error` или `secret`
- **THEN** она не скрывается project suppression, baseline или test-data filter

#### Scenario: Strict project configuration
- **WHEN** `.secscan.toml` содержит неизвестный key или некорректное правило
- **THEN** scan завершается configuration error вместо молчаливого игнорирования

#### Scenario: Suppression accounting
- **WHEN** suppression удаляет finding целиком или частично
- **THEN** summary считает удалённые findings, places и advisories
- **AND** один элемент учитывается только первым применившимся механизмом

### Requirement: Baselines

Система SHALL записывать unfiltered normalized findings в versioned baseline и сравнивать последующие runs по stable identity и growth.

#### Scenario: New finding
- **WHEN** finding отсутствует в baseline
- **THEN** она присутствует в baseline-filtered report как new

#### Scenario: Expanded finding
- **WHEN** известная finding появляется в новых locations или получает новые advisories
- **THEN** report помечает её как expanded
- **AND** содержит только новый участок

#### Scenario: Incompatible baseline
- **WHEN** baseline schema или fingerprint algorithm несовместимы
- **THEN** secscan отказывается сравнивать их без явного migration

### Requirement: Scoped scans

Система SHALL принимать до 16 file или directory scopes и раскрывать, какие scanners сузились, а какие анализировали весь repository.

#### Scenario: Narrowed scanner
- **WHEN** scanner поддерживает target filtering
- **THEN** ему передаются только выбранные tracked и untracked files

#### Scenario: Whole-repository scanner
- **WHEN** scanner не поддерживает безопасный scope
- **THEN** он анализирует весь repository
- **AND** report не приписывает его findings выбранному файлу

#### Scenario: Scope and baseline conflict
- **WHEN** пользователь одновременно запрашивает scoped scan и baseline operation
- **THEN** CLI отклоняет комбинацию как usage error

### Requirement: Reproducibility

Система SHALL закреплять scanner images по digest и записывать фактические image references и rule/feed state в report.

#### Scenario: Pinned scanner image
- **WHEN** scanner container запускается
- **THEN** используется image reference с immutable digest
- **AND** фактический reference записывается в coverage metadata

#### Scenario: Cached rules
- **WHEN** пользователь выбирает content-addressed cached Semgrep rules
- **THEN** тот же cache ID обозначает одинаковые canonical rule bytes
- **AND** scan может использовать их без сети

#### Scenario: Pinned feeds
- **WHEN** пользователь включает pinned advisory feeds
- **THEN** Trivy и Grype используют уже загруженные local databases
- **AND** secscan отказывается выдавать обычный scan при отсутствии требуемой базы

### Requirement: OCI image scanning

Система SHALL обнаруживать literal image references в Dockerfiles, Kubernetes manifests и Compose files, но SHALL загружать их только при `--scan-images`.

#### Scenario: Explicit consent
- **WHEN** images обнаружены без `--scan-images`
- **THEN** ни один registry request для них не выполняется
- **AND** report сообщает количество непросканированных images

#### Scenario: Image ownership
- **WHEN** secscan загружает отсутствующий image
- **THEN** image удаляется после run
- **WHEN** image существовал до run
- **THEN** secscan его не удаляет

### Requirement: Report rendering

Система SHALL строить JSON v1, offline HTML и SARIF 2.1.0 из одной immutable canonical scan model.

#### Scenario: HTML safety
- **WHEN** paths, messages или snippets содержат HTML markup
- **THEN** offline report отображает их как text
- **AND** не выполняет scripts и не загружает внешние resources

#### Scenario: SARIF completeness
- **WHEN** пользователь запрашивает SARIF
- **THEN** SARIF содержит полный unfiltered canonical result set
- **AND** coverage limitations сохраняются в run properties и notifications

#### Scenario: Token budget
- **WHEN** JSON превышает `--max-tokens`
- **THEN** secscan применяет документированный deterministic filter policy
- **AND** report сообщает итоговый floor и удалённые counts
- **AND** JSON остаётся структурно полным

### Requirement: LLM analysis

Система SHALL выполнять brief и explain только после явного opt-in и только после сохранения deterministic report.

#### Scenario: Untrusted repository
- **WHEN** report или source snippets передаются модели
- **THEN** repository text обрабатывается как untrusted data
- **AND** project instructions, hooks и tools отключены

#### Scenario: Credential isolation
- **WHEN** finding имеет kind `secret`
- **THEN** модели передаются только redacted metadata
- **AND** source snippet не передаётся

#### Scenario: LLM failure
- **WHEN** provider недоступен или возвращает invalid output
- **THEN** основной report сохраняется без изменений
- **AND** команда явно сообщает об ошибке annotation stage

### Requirement: Supported environments

Система SHALL выпускать standalone binaries для Linux amd64/arm64 и macOS amd64/arm64.

#### Scenario: CI execution
- **WHEN** stdout не является TTY
- **THEN** progress выводится построчно в stderr без animation

#### Scenario: Unsupported host
- **WHEN** host platform или scanner architecture не поддерживается
- **THEN** affected scanner помечается failed или skipped с точной причиной
- **AND** остальные scanners продолжают работу.

### Requirement: Development traceability

Репозиторий SHALL поддерживать машинно-проверяемые связи между OpenSpec
requirements, реализующими components и подтверждающими tests без создания
второго task tracker или копии текста требований.

#### Scenario: Trace links
- **WHEN** trace verifier проверяет change
- **THEN** каждый scenario из delta spec либо связан с target component и test paths, либо явно deferred со ссылкой на Beads issue
- **AND** component и test paths существуют для завершённого target

#### Scenario: Phased evidence
- **WHEN** выполняется `baseline`, `target` или `final` verification
- **THEN** evidence содержит phase, авторитетный baseline commit, точный ID дочернего Beads outcome, результаты всех phase checks с argv, cwd, exit code и duration, identity проверенного implementation scope и canonical authority hash outcome
- **AND** verifier подтверждает принадлежность outcome к epic из `.br-link`
- **AND** изменение implementation scope после проверки делает предыдущее evidence несвежим
- **AND** изменение title, description, acceptance criteria или dependencies связанной Beads-задачи делает предыдущее evidence несвежим
- **AND** последующая запись evidence, timestamp или lifecycle status в Beads не изменяет canonical authority hash

#### Scenario: Scope verification
- **WHEN** verifier сравнивает baseline commit с текущим committed и working-tree состоянием
- **THEN** каждый добавленный, изменённый, удалённый или переименованный файл входит в declared implementation scope, governance scope или evidence sinks
- **AND** для переименования scope проверяет исходный и целевой paths
- **AND** выход за scope завершает проверку ошибкой с перечислением путей
