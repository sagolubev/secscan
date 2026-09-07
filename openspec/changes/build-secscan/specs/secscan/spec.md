## ADDED Requirements

### Requirement: CLI contract

Система SHALL предоставлять команду `secscan [flags] [path]`, где `path` по умолчанию равен текущему каталогу и разрешается в корень содержащего его Git worktree.

#### Scenario: Machine-readable stdout
- **WHEN** пользователь запускает scan без файлового output override
- **THEN** stdout содержит ровно один JSON-документ schema v1
- **AND** progress и diagnostics направляются только в stderr

#### Scenario: Exit status
- **WHEN** scan завершился, хотя бы один scanner успешно выполнил анализ и все явно запрошенные integration exports выполнены
- **THEN** процесс завершается с кодом `0` независимо от количества findings
- **WHEN** scan не состоялся, все scanners завершились ошибкой или явно запрошенный integration export не выполнен
- **THEN** процесс завершается с кодом `1`
- **WHEN** аргументы некорректны
- **THEN** процесс завершается с кодом `2`
- **WHEN** все выбранные personas skipped из-за отсутствия поддерживаемых inputs
- **THEN** процесс возвращает report с явным skipped coverage и код `0`

#### Scenario: Failure evidence
- **WHEN** начатый scan завершается ошибкой после сбора findings или scanner evidence
- **THEN** доступный canonical report сохраняется как один JSON document с явными failed statuses
- **AND** процесс возвращает exit code `1`, если успешного scanner нет
- **AND** ошибки до начала scan, включая недоступный runtime, не создают вымышленный report

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
- **AND** cancellation завершает и удаляет принадлежащий run контейнер, не затрагивая чужие containers

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
- **WHEN** stderr является TTY, `TERM` не равен `dumb`, progress mode равен `auto` или `tty` и scanner rows помещаются в окно
- **THEN** secscan перерисовывает фиксированный dashboard со строкой на каждый scanner
- **AND** строка показывает текущую stage, elapsed-time bar, findings count и итоговый status
- **AND** завершение или ошибка восстанавливают cursor и оставляют финальный dashboard видимым

#### Scenario: Terminal height
- **WHEN** полный набор scanner rows помещается в TTY, но журнал превышает доступную высоту
- **THEN** видимый журнал сокращается так, чтобы dashboard помещался в окно без потери scanner rows
- **WHEN** окно слишком мало для scanner rows
- **THEN** progress переключается на plain events с восстановленным cursor

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
- **THEN** report перечисляет их как unread или unchecked с path, категорией и причиной
- **AND** отдельно раскрывает неклассифицированные файлы, не заявляя для них SAST/SCA coverage
- **AND** отсутствие scanner selection, failed/skipped scanner и отсутствие per-input evidence не выдаются за успешный анализ

#### Scenario: Traversal disclosure
- **WHEN** ignored или untracked directories исключены из обхода
- **THEN** report сообщает eligible tracked/untracked и ignored file/byte counts и отдельные non-recursive directory counts
- **AND** symlinks, deleted entries, non-regular files и явно исключённые control files перечислены с причиной без чтения их содержимого
- **AND** filesystem scanners, включая Gitleaks, получают только безопасные nonignored regular files
- **AND** inventory не выдаётся за доказательство scanner read coverage

### Requirement: Filtering and suppressions

Система SHALL применять исключения в порядке: native scanner waivers, project suppressions, baseline, severity floor, test-data policy.

#### Scenario: Exempt findings
- **WHEN** finding имеет kind `error` или `secret`
- **THEN** она не скрывается project suppression, baseline или test-data filter
- **AND** severity floor также сохраняет secret/error findings

#### Scenario: Strict project configuration
- **WHEN** `.secscan.toml` содержит неизвестный key или некорректное правило
- **THEN** scan завершается configuration error вместо молчаливого игнорирования
- **AND** version=1, bounded regular-file input, selector grammar и уникальные suppression ids проверяются до запуска scanners
- **AND** parser errors не раскрывают содержимое config; --config выбирает явный файл, --no-config отключает project policy

#### Scenario: Suppression accounting
- **WHEN** suppression удаляет finding целиком или частично
- **THEN** summary считает удалённые findings, places и advisories
- **AND** один элемент учитывается только первым применившимся механизмом
- **AND** partial advisory/location combinations сохраняются отдельными fragments с исходным fingerprint и счётчиком removed occurrences

#### Scenario: Ordered visible filtering
- **WHEN** одновременно заданы project rules, baseline, severity floor или test-data paths
- **THEN** видимый report применяет их в указанном порядке с отдельными counts каждого этапа
- **AND** unknown severity, scanner coverage и inventory не превращаются в скрытые пробелы анализа
- **AND** baseline snapshots, SARIF и Trivy integration reports получают полный unfiltered scan

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

#### Scenario: Severity growth
- **WHEN** известная finding получает более высокий severity
- **THEN** она остаётся видимой как expanded, даже если locations и advisory IDs не изменились

#### Scenario: Baseline data boundary
- **WHEN** пользователь читает baseline
- **THEN** принимается только ограниченный по размеру versioned JSON с совместимым fingerprint algorithm, без исполнения содержимого
- **AND** старые messages и source text не попадают в новый report
- **WHEN** пользователь записывает baseline
- **THEN** сохраняются полные нормализованные findings текущего scan до фильтрации и integration exports
- **AND** существующий output не перезаписывается, а failure не публикует частичный snapshot

#### Scenario: Baseline report accounting
- **WHEN** baseline применяется к report
- **THEN** coverage и exclusions сохраняются, report содержит counts new/expanded/unchanged/exempt и статус у видимых findings
- **AND** одновременно новые advisories и locations сохраняются без потери новых сочетаний
- **AND** --baseline и --write-baseline взаимоисключаются и недоступны для update
- **AND** выбранные baseline control files не сканируются и перечислены как явно исключённые inputs

### Requirement: Source navigation comments

Затрагиваемые ключевые Go-модули SHALL содержать короткие GRACE module contracts/maps с существующими путями требований и тестов.

#### Scenario: Navigable boundaries
- **WHEN** агент открывает discovery, report normalization, CLI или baseline code
- **THEN** видны PURPOSE, существенные SCOPE ограничения, карта реальных символов и ссылки на проверяющие tests
- **AND** сложные trust/filtering boundaries имеют отдельные короткие контракты функций
- **AND** комментарии не копируют task status/evidence и не требуют отдельной .grace модели

#### Scenario: Automated markup checks
- **WHEN** проверяется новый или изменённый Go module в cmd/ или internal/
- **THEN** contract/map обязателен, marker pairs и ROLE/MAP_MODE согласованы, symbols/exports/links проверяются по AST и файлам
- **AND** CI проверяет разметку и текущую evidence chain, сохраняя остальные обязательные gates

### Requirement: Scoped scans

Система SHALL принимать до 16 file или directory scopes и раскрывать, какие scanners сузились, а какие анализировали весь repository.

#### Scenario: Narrowed scanner
- **WHEN** scanner поддерживает target filtering
- **THEN** ему передаются только выбранные tracked и untracked files
- **AND** --scope принимает до 16 относительных Git paths; invalid, symlink, missing или не выбирающий eligible files scope отклоняется без ложного clean result
- **AND** пересечения scopes не дублируют inputs, а report раскрывает requested paths и фактическую область каждого scanner

#### Scenario: Whole-repository scanner
- **WHEN** scanner не поддерживает безопасный scope
- **THEN** он анализирует весь repository
- **AND** report не приписывает его findings выбранному файлу

#### Scenario: Scope and baseline conflict
- **WHEN** пользователь одновременно запрашивает scoped scan и baseline operation
- **THEN** CLI отклоняет комбинацию как usage error
- **AND** update также отклоняет --scope

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

#### Scenario: OCI archive boundary
- **WHEN** передан --scan-images и обнаружен literal image reference
- **THEN** host runtime экспортирует image archive для Trivy и Grype
- **AND** scanner containers не получают container socket
- **AND** network capability и image digest отражены в evidence

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

#### Scenario: Report publication
- **WHEN** пользователь передаёт --html FILE или --sarif FILE для scan
- **THEN** JSON stdout сохраняется, HTML показывает видимый report, а SARIF содержит unfiltered findings
- **AND** output публикуется как новый полный файл в заранее открытом parent directory без замены существующих files или symlinks
- **AND** output внутри worktree исключается как control file до scanner staging
- **AND** ошибка render/write сохраняет JSON и даёт exit1; attempted failed scan сохраняет failed coverage и exit1
- **WHEN** output flag пуст или передан для update
- **THEN** команда возвращает usage exit code 2 до запуска scanners

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

#### Scenario: Complete Git snapshot
- **WHEN** HEAD, index или working tree отличаются от baseline
- **THEN** scope учитывает объединение изменений всех трёх состояний, включая rename sources и untracked files
- **AND** identity различает index и рабочую копию; восстановление рабочей копии не скрывает staged bytes
- **AND** baseline является неизменяемым commit ID, а target/final отклоняют расхождение index и проверяемых файлов

#### Scenario: Manifest-bound verification
- **WHEN** verifier загружает manifest
- **THEN** он принимает только ограниченный regular JSON внутри repository и связывает его фактические bytes и path с identity/evidence
- **AND** замена manifest во время checks отклоняется, а произвольные evidence sinks запрещены

#### Scenario: Trace reference validation
- **WHEN** trace содержит deferred issue или test reference
- **THEN** issue существует в Beads и принадлежит change, а test reference указывает допустимый test file или Go test symbol
- **AND** README вместо test и несуществующий Beads ID отклоняются

#### Scenario: Preimplementation baseline
- **WHEN** запускается baseline
- **THEN** implementation scope ещё не изменён относительно anchor
- **AND** evidence фиксирует время запуска и завершения; поздний baseline не выдаётся за исходное состояние

#### Scenario: Durable evidence chain
- **WHEN** выполняется phase check
- **THEN** полный versioned record сохраняется через br comments и переносится с JSONL
- **AND** target ссылается на matching successful baseline, final на fresh successful target, с digest links и корректным порядком времени
- **AND** проверка сохранённой цепочки подтверждает текущие code/index/manifest/authority без повторного запуска scanners

#### Scenario: Legacy evidence retention
- **WHEN** сохраняются существующие v1 или bootstrap records
- **THEN** их исходные данные и ограничения явно помечены legacy и не удовлетворяют новым phase gates
- **AND** отклонение baseline .17 сохраняется без выдуманных прошлых timestamps или успешных проверок

#### Scenario: Structured verification results
- **WHEN** исполняется объявленный go-test-json check
- **THEN** evidence содержит passed/failed/skipped counts и ограниченную metadata output без сырых snippets
- **AND** all-skipped acceptance не считается успешным выполненным анализом

### Requirement: Scanner preparation

Система SHALL отделять разрешённые загрузки от offline scan командой `secscan update [--scanners ...] [path]`.

#### Scenario: Atomic preparation
- **WHEN** update успешно загружает pinned images и необходимые databases
- **THEN** публикуется manifest с immutable image IDs, content digests и временем подготовки
- **AND** ошибка или interruption оставляет предыдущий manifest и snapshots пригодными для scan

#### Scenario: Offline scan
- **WHEN** запускается обычный scan
- **THEN** image pull, image build, version checks и database downloads запрещены
- **AND** отсутствие image или требуемого database snapshot даёт failed coverage и actionable diagnostic

#### Scenario: Feed integrity and freshness
- **WHEN** dependency scanner открывает database snapshot
- **THEN** проверяются digest и возраст не более пяти суток
- **AND** испорченный, отсутствующий или просроченный snapshot не считается успешной проверкой

### Requirement: CI scanners

Система SHALL выполнять Zizmor и Poutine только над локальными CI definitions.

#### Scenario: Local CI analysis
- **WHEN** Git inventory содержит поддерживаемые CI definitions
- **THEN** Zizmor и Poutine запускаются offline в hardened containers
- **AND** canonical findings содержат rule, severity и one-based location без source snippets

#### Scenario: Offline CI limitations
- **WHEN** Zizmor выполняется без API access
- **THEN** coverage явно указывает исключение online audits
- **AND** отсутствие подходящих CI files даёт skipped, не success

### Requirement: IaC scanners

Система SHALL поддерживать Checkov, Checkov Terraform и KICS.

#### Scenario: Separate Checkov scopes
- **WHEN** выбран Checkov
- **THEN** persona checkov-terraform анализирует Terraform, OpenTofu и Terraform plans
- **AND** persona checkov исключает эти frameworks и remote-only checks
- **AND** external modules и policy downloads выключены

#### Scenario: KICS analysis
- **WHEN** repository содержит поддерживаемые IaC files
- **THEN** KICS использует pinned upstream v2.1.20 image и embedded queries
- **AND** failed files или queries отражены в coverage

### Requirement: Dependency scanners

Система SHALL поддерживать Trivy, Grype и OSV-Scanner с локальными advisory snapshots.

#### Scenario: Offline dependency findings
- **WHEN** repository содержит поддерживаемые manifests или lockfiles
- **THEN** dependency scanners читают только локальные inputs и подготовленные feeds
- **AND** findings содержат package identity, version, advisory IDs и source locations

#### Scenario: Advisory alias merge
- **WHEN** разные scanners связывают одну package version с пересекающимися advisory aliases
- **THEN** report объединяет findings транзитивно, сохраняя aliases, sources и locations
- **AND** различающиеся package versions не объединяются

#### Scenario: Partial extraction
- **WHEN** scanner не может прочитать manifest или требует отсутствующий ecosystem feed
- **THEN** input отражается как unread или failed
- **AND** пустой JSON от аварийно завершившегося scanner не считается успешным анализом

### Requirement: Additional code scanners

Система SHALL поддерживать Semgrep, Bearer и Cppcheck.

#### Scenario: Semgrep rules and merge
- **WHEN** Semgrep сканирует Python или TypeScript
- **THEN** он использует тот же project-owned MIT rule pack, что Opengrep
- **AND** одинаковые findings объединяются со списком обоих source engines

#### Scenario: Bearer architecture
- **WHEN** runtime architecture равна amd64 и есть поддерживаемый source input
- **THEN** используется pinned upstream Bearer image без redistribution
- **WHEN** runtime architecture не поддерживается
- **THEN** Bearer получает skipped с явной причиной без emulation

#### Scenario: Bearer offline rules
- **WHEN** Bearer выполняет scan
- **THEN** он использует подготовленный pinned rule pack без default rule downloads, version checks или domain resolution
- **AND** rule bytes и ELv2 license хранятся только в private cache, не в распространяемом исходном коде secscan
- **AND** static rule identity проверяется по digest и version без срока годности advisory feeds

#### Scenario: Cppcheck source build
- **WHEN** выбран Cppcheck и есть C/C++ files
- **THEN** scan использует project-owned image из закреплённого upstream source
- **AND** source hash, license и build recipe доступны вместе с image
- **AND** scan не запускает build scripts проверяемого проекта

### Requirement: Static Gradle analysis

Система SHALL анализировать Gradle metadata без выполнения Groovy, Kotlin или Gradle wrapper.

#### Scenario: Catalog coordinates
- **WHEN** version catalog содержит literal coordinates или разрешимые version references
- **THEN** gradle-catalog извлекает Maven package inventory для offline vulnerability lookup
- **AND** unresolved entries учитываются как unread

#### Scenario: Script coordinates
- **WHEN** build.gradle или build.gradle.kts содержит literal dependency coordinates
- **THEN** gradle-scripts извлекает их для offline vulnerability lookup
- **AND** dynamic expressions и plugins не считаются полностью разрешёнными dependencies

#### Scenario: Refresh versions metadata
- **WHEN** существует versions.properties
- **THEN** refresh-versions читает только файл и существующие update comments
- **AND** сообщает configuration findings, не заявляя vulnerability coverage

### Requirement: Open-source distribution

Система SHALL публиковаться в public sagolubev/secscan с MIT для собственного кода и сохранением third-party notices.

#### Scenario: Public module and licensing
- **WHEN** пользователь получает исходники или бинарник
- **THEN** canonical Go module соответствует github.com/sagolubev/secscan
- **AND** MIT license и обязательные third-party notices доступны, включая --licenses в standalone executable
- **AND** внешние scanner engines/rules не перелицензируются и не включаются в release assets

#### Scenario: Release identity
- **WHEN** пользователь запускает secscan --version
- **THEN** выводится версия сборки без Git worktree или container runtime

### Requirement: Continuous verification and releases

GitHub Actions SHALL проверять source changes и публиковать release только после успешных gates.

#### Scenario: Pull request and branch checks
- **WHEN** открыт pull request или отправлен commit в default branch
- **THEN** выполняются formatting, module integrity, vet, tests/race, workflow validation, trace/staleness checks и сборка Linux/macOS amd64/arm64
- **AND** реальные container acceptance выполняются на Linux с явными readiness limits для недоступных runtime/platforms
- **AND** PR jobs не получают write permissions или publish secrets

#### Scenario: Portable trace validation
- **WHEN** CI проверяет trace manifest в новом checkout
- **THEN** проверяются exact scenario links, declared full diff scope, Beads authority и artifact staleness
- **AND** validation-only output не выдаётся за выполненные phase checks/evidence

#### Scenario: Binary release
- **WHEN** push корректного version tag запускает release workflow
- **THEN** после gates создаётся GitHub Release с четырьмя single-file executables и SHA256 checksums
- **AND** release не содержит scanner images, feeds или development tools
- **AND** загруженные artifacts проверяются на целевых OS и соответствуют version tag

### Requirement: GRACE pilot evaluation

Оценка SHALL опираться на проверенные repository artifacts и разделять verifier, workflow и независимое review.

#### Scenario: Evidence-based assessment
- **WHEN** подводятся итоги пилота
- **THEN** документ перечисляет наблюдаемые гарантии, найденные ограничения и стоимость поддержки
- **AND** измеренные counts отделены от качественных выводов и отсутствующих измерений

### Requirement: Trivy integration reports

Система SHALL по `--trivy-reports DIR` создавать CycloneDX 1.6 SBOM и SonarQube Server Generic Issues JSON из одного offline Trivy scan зависимостей репозитория.

#### Scenario: Complete package inventory
- **WHEN** Trivy успешно извлёк все выбранные поддерживаемые dependency inputs
- **THEN** `trivy.cdx.json` содержит все обнаруженные пакеты, включая пакеты без уязвимостей, с корректными PURL и уникальными bom-ref
- **AND** известные связи зависимостей ссылаются на существующие компоненты, а отсутствующие связи не выдумываются
- **AND** SBOM соответствует CycloneDX 1.6 и пригоден для Dependency-Track 4.12+

#### Scenario: SonarQube external issues
- **WHEN** Trivy сообщил уязвимости в зависимостях репозитория
- **THEN** `trivy.sonarqube.json` содержит согласованные rules и issues для `sonar.externalIssuesReportPaths` в SonarQube Server 10.3+
- **AND** primaryLocation указывает проверенный относительный путь к реально выбранному manifest без выдуманного textRange
- **AND** severity и SECURITY impacts определяются детерминированно, а чистый scan создаёт пустые массивы

#### Scenario: Explicit export failure
- **WHEN** requested Trivy scan failed, skipped, has unread/failed inputs, or lacks verified package inventory
- **THEN** процесс возвращает exit code 1, сохраняет доступный canonical JSON stdout и не создаёт экспорт, похожий на полный успешный результат
- **WHEN** --trivy-reports совмещён с update или выбором scanners без trivy
- **THEN** CLI возвращает usage exit code 2 до запуска scanners

#### Scenario: Safe output files
- **WHEN** пользователь запросил экспорт в новый каталог вне Git worktree
- **THEN** создаются только два оговорённых JSON файла после завершения Trivy
- **AND** существующий каталог, файл или symlink назначения не перезаписывается
- **AND** raw scanner text, descriptions, snippets, credentials in URLs и произвольные properties не копируются в экспорт
- **AND** обычный JSON stdout не включает payload экспортных файлов

#### Scenario: Import documentation
- **WHEN** пользователь читает инструкции экспорта
- **THEN** документация указывает версии форматов, загрузку SBOM в Dependency-Track и property импорта SonarQube
- **AND** поясняет, что Dependency-Track анализирует inventory самостоятельно, а SonarQube импортирует замечания только для проиндексированных файлов
- **AND** repository dependency export не выдаётся за OCI image SBOM или SARIF экспорт всех scanners

### Requirement: Single-command binary installation

Система SHALL предоставлять самостоятельный POSIX install.sh для установки опубликованного бинарника одной командой `curl ... | sh`.

#### Scenario: Platform and version selection
- **WHEN** installer запущен на Linux или macOS с amd64/x86_64 либо arm64/aarch64
- **THEN** выбирается соответствующий release executable
- **AND** default latest разрешается один раз в конкретный стабильный tag, общий для binary и SHA256SUMS
- **AND** --version и --dir задают конкретную версию и каталог; default directory равен ~/.local/bin
- **AND** неподдерживаемая платформа и некорректные аргументы отклоняются без установки

#### Scenario: Verified atomic replacement
- **WHEN** installer скачал бинарник и SHA256SUMS через HTTPS
- **THEN** требуется ровно одна корректная checksum entry для выбранного файла и совпадение SHA256 до исполнения или установки
- **AND** проверенный executable должен сообщить ожидаемую версию через --version
- **AND** подготовленный файл заменяет прежний secscan через rename внутри filesystem каталога установки

#### Scenario: Installation failure isolation
- **WHEN** download, checksum, version check или filesystem operation завершается ошибкой
- **THEN** installer возвращает ненулевой exit code и сохраняет прежний бинарник
- **AND** временные файлы installer удаляются
- **AND** существующие directory или symlink с именем secscan не заменяются
- **AND** installer не вызывает sudo, не меняет shell profiles и не готовит scanner assets

#### Scenario: Installation instructions and tests
- **WHEN** пользователь открывает README
- **THEN** первым способом установки показана одна curl-to-sh команда, а также выбор версии/каталога и условие PATH
- **AND** installer tests проверяют платформы, upgrade, checksum/download failures и сохранение существующих файлов на Linux и macOS в CI
