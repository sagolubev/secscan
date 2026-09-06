# Что умеет secscan и чего пока не хватает

Срез на 6 сентября 2026 года, commit
[`c406ed3`](https://github.com/sagolubev/secscan/tree/c406ed3a1deaf18259c0053f75a7e8a5eaaa623e).
Secscan уже запускает весь согласованный набор сканеров, но пользовательские
возможности DietSec реализованы не целиком. Главные пробелы — история Git,
фильтры, сравнение с прошлым отчётом, выбор отдельных файлов и форматы отчётности.

Сравнение основано на [русской странице DietSec][dietsec] и его
[описании схемы и ограничений][dietsec-llm], прочитанных в эту дату.
Для DietSec это заявления автора: его бинарник здесь не запускался.
Исходный GitLab-проект получить не удалось: публичный API вернул 404,
Git запросил авторизацию. Поэтому версия его исходников не зафиксирована.

Для secscan проверены CLI, код, тесты, [спецификация][spec] и [trace manifest][trace].
[CI этого commit][ci] завершилась успешно, включая контейнерные acceptance-тесты
на Linux amd64/arm64 и запуск четырёх нативных бинарников. Такие тесты проверяют
конкретные примеры, а не весь набор возможностей внешнего движка.
Задачи и их текущее состояние остаются в Beads; этот документ — снимок продукта.

## Сканирование

В CLI 18 personas — отдельно выбираемых заданий. По умолчанию выбраны 17;
`oci-images` требует `--scan-images`. Две дополнительные personas относительно
списка DietSec — Python и TypeScript на Opengrep. Это не два новых независимых
набора правил: Semgrep использует тот же пакет.

| Область | Что есть в secscan | Граница проверки |
| --- | --- | --- |
| Секреты | Gitleaks проверяет рабочее дерево; значения секретов и фрагменты исходников не входят в JSON | Команда `dir`, без прошлых коммитов. Контейнерный тест проверяет синтетический секрет и его удаление из отчёта. [Код и тест][gitleaks] |
| Python | `python-sast` на Opengrep и `semgrep`: три правила для `eval`/`exec`, `shell=True`, небезопасного `yaml.load` | Выбираются `.py`/`.pyi`. Это небольшой набор шаблонов, не общее доказательство безопасности Python или его фреймворков. [Правила][rules], [acceptance][opengrep-test] |
| TypeScript | `typescript-sast` и `semgrep`: пять правил для динамического кода, shell-команд, `innerHTML`, отключённой TLS-проверки и случайных токенов | Выбираются `.ts`/`.tsx`/`.mts`/`.cts`. Наличие расширения в inventory не означает проверку всех синтаксических форм. [Правила][rules], [acceptance][opengrep-test] |
| Другие языки | Bearer получает кандидаты Java, Python, Ruby, JavaScript/TypeScript, PHP и Go; Cppcheck — C/C++ | Bearer работает только на native amd64. Его acceptance доказывает случай с Python `pickle.loads`, не все языки. SARIF подтверждает только файлы с находками; остальные остаются unread, пустой неподтверждённый результат даёт failure. Cppcheck проверен на C++ примерах; compiler flags, внешние headers и addons не передаются. [Код][code], [тесты][code-test] |
| Зависимости | Trivy, Grype и OSV читают выбранные локальные manifests/lockfiles и подготовленные базы; совпадающие advisory aliases объединяются | Реальный совместный тест использует npm lockfile. Нет установки зависимостей, разрешения версий и Go call analysis. Trivy здесь запускается только для vulnerabilities, без IaC-проверки. [Код][deps], [тесты][deps-test] |
| CI | Zizmor: локальные GitHub workflows/actions, Dependabot и pre-commit. Poutine: GitHub, корневой GitLab CI, Azure и выбранные Tekton definitions | Acceptance содержит находки для GitHub, GitLab, Azure, Tekton и pre-commit. Это не обещание проверки всех классов ошибок этих платформ. GitLab includes не раскрываются; API-аудиты Zizmor выключены; неподдерживаемые Tekton shapes отклоняются. [Код][ci-code], [тесты][ci-test] |
| IaC | Checkov, отдельный Checkov Terraform и KICS; входы Terraform/OpenTofu, JSON, YAML и Dockerfile | Acceptance проверяет Terraform, OpenTofu, Terraform JSON/plan и примеры Dockerfile/Kubernetes. Модули и политики не скачиваются, manifests не рендерятся. `.bicep` не входит в inventory. Наличие Compose YAML среди кандидатов не заменяет отдельный acceptance для Compose. [Inventory][inventory], [тесты][iac-test] |
| Gradle | Каталоги версий и build scripts дают literal Maven coordinates для offline lookup; `refresh-versions` читает существующие hints | Wrapper, Groovy/Kotlin и plugins не исполняются. Dynamic expressions, ranges и неразрешённые ссылки остаются unread. `refresh-versions` сообщает о конфигурации, не о CVE или текущей доступности обновления. [Код и тесты][native] |
| OCI images | По явному флагу host runtime загружает и экспортирует literal image references; Trivy и Grype читают архив | Образы не запускаются, socket в контейнеры не передаётся. Собственные загрузки удаляются, прежние образы сохраняются. Шаблоны Helm, переменные, выбор build stage и platform не вычисляются. [Код][oci], [acceptance][oci-test] |

Allowlist зависимостей: `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `go.mod`, `go.sum`, `requirements.txt`, `Pipfile.lock`,
`poetry.lock`, `uv.lock`, `Cargo.lock`, `composer.lock`, `Gemfile.lock`,
`packages.lock.json`. Файл из этого списка может остаться unread, если движок
не извлёк пакеты. `pom.xml`, `gradle.lockfile`, `bun.lock` и `packages.config`
распознаются как кандидаты, но в этот проход не передаются. `.csproj` вообще
не входит в inventory. Это уже, чем перечень DietSec. [Источник][deps]

## Работа с результатом

| Возможность из DietSec | Secscan на дату среза |
| --- | --- |
| Один бинарник, Docker/Podman | Четыре бинарника Linux/macOS × amd64/arm64. Docker подтверждён acceptance; Podman и rootless ещё не подтверждены. Cppcheck собирается и работает native arm64, Bearer там пропускается без эмуляции. |
| Параллельные сканеры, частичные ошибки | Есть ограниченная параллельность, timeout/cancellation, сохранение частичного JSON и error findings. Findings сами по себе не меняют exit code; полный отказ сканирования даёт `1`, ошибка аргументов — `2`. [CLI][cli] |
| Живой прогресс и обычный лог | Есть `auto`, `tty`, `plain`, `off`, учёт размера терминала и `NO_COLOR`. Полоса означает прошедшее время, не процент готовности. Четырёх языков интерфейса и `--lang` нет. [Progress][progress] |
| Компактный JSON и дедупликация | Есть собственная schema v1, стабильные fingerprints, сортировка, объединение dependency aliases и одинаковых правил Semgrep/Opengrep. Нет таблицы общих путей, token budget и совместимости с DietSec Schema 4. Правила разных IaC-движков не сводятся вручную в одно. [Модель][report] |
| Coverage, unread/unchecked | Есть статусы сканеров, единицы счёта, unread/failed inputs и limitations. Единого перечня всех неподдерживаемых языков, фреймворков и экосистем пока нет. Пустой findings не означает, что всё дерево проверено. |
| Ignored/untracked/walked, `--scan-ignored` | Для staging учитываются tracked и untracked nonignored файлы. В JSON есть лишь общие ignored file/byte counts, без списка каталогов и полного walked inventory. Gitleaks отдельно получает корень worktree. Общего переключателя обхода нет. [Inventory][inventory], [модель][report] |
| Severity, test-data, dev-deps, resolved-versions | Пользовательских фильтров нет. Нет и сводки об отфильтрованном. Разрешение зависимостей отключено, поэтому механизм DietSec для отбрасывания выбранных resolver-ом версий сюда напрямую не переносится. |
| Native waivers и `.dietsec.toml` | `.secscan.toml` и общего учёта suppressions нет. Staged adapters исключают конфиги репозитория; отдельные inline suppressions движков остаются. Это не эквивалент механизму DietSec с повторным запуском и квитанцией о скрытых находках. [Design][design] |
| `--baseline`, `--write-baseline` | Нет сравнения результатов сканирования с прошлым отчётом. GRACE `baseline` относится к проверкам разработки и не заменяет эту функцию. |
| `--scope` | Нет. Переданный путь разрешается в корень Git worktree; путь к подкаталогу не сужает scan. GRACE scope проверяет diff разработки, а не выбирает файлы сканирования. |
| `--html`, `--sarif`, `--max-tokens` | Нет. SARIF разбирается внутри некоторых adapters, но экспорт SARIF отсутствует. JSON сохраняется перенаправлением stdout; отдельного `--out` нет. |
| `--brief`, `--explain`, `--model` | Нет вызовов LLM и рекомендаций в отчёте. Все сообщения findings задаёт код secscan; source snippets в канонической модели отсутствуют. |
| Digest pins, `--use-cache`, `--pin-feeds` | Подготовка вынесена в `update`; обычный scan не скачивает движки, правила или базы. Используются закреплённые правила и проверенные snapshots, в том числе OSV. Advisory feeds старше пяти суток отклоняются. Произвольного пользовательского rule cache ID нет. [Preparation][preparation] |
| `--purge`, настройка timeout | Команд очистки и пользовательского `--timeout` нет. Общий лимит CLI — десять минут. [CLI][cli] |
| Лицензия | Собственный код secscan — MIT, notices доступны через `--licenses`. DietSec заявляет TDWPL-67. Лицензии внешних движков и правил сохраняются. |

## Что осталось по нашим требованиям

[Trace manifest][trace] содержит 76 scenarios: 56 помечены `target`, 20 —
`deferred`, со ссылкой на Beads epic `secscan-ij8`. Это учёт связей, а не
«74% готовности»: наличие test path не доказывает весь смысл требования.
Ниже все 20 deferred scenarios, сгруппированные по исходным требованиям.
Названия сохранены для поиска в OpenSpec.

| Требование | Deferred scenarios | Что ещё не подтверждено или не реализовано |
| --- | --- | --- |
| [Container runtime][spec-runtime] | `Rootless runtime` | Доступность cache artifacts при user namespace remapping/rootless и реальная совместимость окружений. |
| [Canonical finding model][spec-model] | `Finding origin` | Поиск в истории Git и различение истории с рабочим деревом. Сейчас origin только `working_tree`. |
| [Honest coverage][spec-coverage] | `Unsupported inputs` | Полный учёт форматов и экосистем, для которых нет подходящего анализа. |
| [Filtering and suppressions][spec-filter] | `Exempt findings`; `Strict project configuration`; `Suppression accounting` | Фильтры, `.secscan.toml`, строгая валидация, защита secret/error от скрытия и счётчики исключений. |
| [Baselines][spec-baselines] | `New finding`; `Expanded finding`; `Incompatible baseline` | Сохранение unfiltered результата, сравнение роста и отказ от несовместимого baseline. |
| [Scoped scans][spec-scopes] | `Narrowed scanner`; `Whole-repository scanner`; `Scope and baseline conflict` | Выбор до 16 путей, раскрытие сканеров с полным обходом и проверка конфликтов CLI. |
| [Reproducibility][spec-repro] | `Cached rules` | Пользовательский content-addressed cache правил. Embedded rules с digest уже есть, но это другой контракт. |
| [Report rendering][spec-render] | `HTML safety`; `SARIF completeness`; `Token budget` | Offline HTML, полный SARIF и детерминированное сокращение JSON с отчётом об исключениях. |
| [LLM analysis][spec-llm] | `Untrusted repository`; `Credential isolation`; `LLM failure` | Opt-in brief/explain, изоляция project instructions/hooks и сохранение отчёта при отказе LLM. |
| [Supported environments][spec-env] | `Unsupported host` | Общая обработка неподдерживаемых платформ. Частный случай Bearer arm64 уже покрыт, весь контракт остаётся deferred. |

Есть и пробел в scenario, уже помеченном `target`: `Traversal disclosure`
требует сообщать исключённые каталоги и фактические file/byte counts обхода.
Текущий JSON содержит только `ignoredFiles` и `ignoredBytes`. Перед закрытием
требования нужны проверка смысла coverage и отдельный acceptance; зелёный
tracecheck этого расхождения не обнаруживает. [Требование][spec-coverage],
[реализация][inventory], [JSON][report]

## Что имеет смысл добавить следующим

Для повседневной работы важнее сначала объяснить границы уже выполненного scan:
полный unsupported/traversal inventory, история секретов, проверки Podman и
rootless. Затем baseline diff и scope дадут короткий ответ о текущем изменении,
а HTML/SARIF позволят читать и передавать результат без собственного обработчика.
Это рекомендации по результатам сравнения, не новые обязательства или задачи.

Расширять анализ стоит проверяемыми примерами: Bicep, Compose, Maven/.NET
manifests, дополнительные Python/TypeScript правила и конкретные фреймворки.
Для каждого нужен пример, который находит ожидаемую проблему, и безопасный
контрпример. Увеличение числа scanners или extensions в inventory само по себе
не улучшит доказанное покрытие. Локализацию, очистку cache, LLM и фильтры
зависимостей можно выбирать по реальным сценариям использования. Фильтры DietSec
`--dev-deps`/`--resolved-versions`, очистка cache и локализация пока не оформлены
отдельными acceptance scenarios в нашем OpenSpec.

[dietsec]: https://versinger.gitlab.io/dietsec/ru.html
[dietsec-llm]: https://versinger.gitlab.io/dietsec/llm.md
[ci]: https://github.com/sagolubev/secscan/actions/runs/34050717909
[spec]: ../openspec/changes/build-secscan/specs/secscan/spec.md
[trace]: https://github.com/sagolubev/secscan/blob/c406ed3a1deaf18259c0053f75a7e8a5eaaa623e/openspec/changes/build-secscan/trace.json
[design]: ../openspec/changes/build-secscan/design.md
[cli]: ../cmd/secscan/main.go
[gitleaks]: ../internal/gitleaks/run_test.go
[rules]: ../scanner/opengrep/assets/rules/
[opengrep-test]: ../internal/opengrep/scan_test.go
[code]: ../internal/scanner/code.go
[code-test]: ../internal/scanner/code_test.go
[deps]: ../internal/scanner/dependencies.go
[deps-test]: ../internal/scanner/dependencies_test.go
[ci-code]: ../internal/scanner/ci.go
[ci-test]: ../internal/scanner/ci_test.go
[inventory]: ../internal/discovery/discovery.go
[iac-test]: ../internal/scanner/iac_test.go
[native]: ../internal/scanner/native_test.go
[oci]: ../internal/scanner/oci.go
[oci-test]: ../internal/scanner/oci_test.go
[progress]: ../internal/progress/live.go
[report]: ../internal/report/report.go
[preparation]: ../internal/scanner/prepare.go
[spec-runtime]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-container-runtime
[spec-model]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model
[spec-coverage]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-honest-coverage
[spec-filter]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-filtering-and-suppressions
[spec-baselines]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-baselines
[spec-scopes]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-scoped-scans
[spec-repro]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-reproducibility
[spec-render]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-report-rendering
[spec-llm]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-llm-analysis
[spec-env]: ../openspec/changes/build-secscan/specs/secscan/spec.md#requirement-supported-environments
