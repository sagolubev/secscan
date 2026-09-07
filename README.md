# Secscan

[Скачать](https://github.com/sagolubev/secscan/releases/latest) · [MIT](LICENSE) · [CI](https://github.com/sagolubev/secscan/actions/workflows/ci.yml)

Secscan запускает проверки безопасности локального Git-репозитория и собирает
находки в один JSON-отчёт. Он проверяет секреты, код, зависимости, CI и
инфраструктурные файлы. Во время запуска в терминале виден прогресс каждого сканера.

Для работы нужен один бинарник, Git и запущенный Docker или Podman.
Go, Python и Node.js на компьютере пользователя не нужны: внешние сканеры
работают в контейнерах. Поддержанные режимы runtime описаны ниже.

## Установка

Установить последний стабильный релиз:

```sh
curl -fsSL https://raw.githubusercontent.com/sagolubev/secscan/master/install.sh | sh
```

Скрипт определит Linux/macOS и архитектуру, проверит SHA256 и установит
`secscan` в `~/.local/bin`. Для установки не нужны `sudo`, Go или Docker.
Повторный запуск обновит бинарник. При ошибке скачивания или проверки прежний
бинарник останется на месте.

Чтобы выбрать версию и каталог:

```sh
curl -fsSL https://raw.githubusercontent.com/sagolubev/secscan/master/install.sh | \
  sh -s -- --version v0.4.0 --dir "$HOME/.local/bin"
```

Если `~/.local/bin` ещё не входит в PATH, добавьте его в текущем терминале:

```sh
export PATH="$HOME/.local/bin:$PATH"
secscan --version
```

Для новых терминалов сохраните строку `export PATH=...` в `~/.zshrc` или
`~/.bashrc`. Сам installer не меняет настройки shell.

<details>
<summary>Ручная установка без скрипта</summary>

В [релизе v0.4.0](https://github.com/sagolubev/secscan/releases/tag/v0.4.0)
выберите файл для своей системы:

| Система | Процессор | Файл |
|---|---|---|
| Linux | x86-64 | `secscan-linux-amd64` |
| Linux | ARM64 | `secscan-linux-arm64` |
| macOS | Intel | `secscan-darwin-amd64` |
| macOS | Apple Silicon | `secscan-darwin-arm64` |

Архитектуру показывает `uname -m`: `x86_64` соответствует amd64,
`arm64` или `aarch64` — arm64.

Скачайте бинарник и контрольные суммы. В примере выбран Mac с Apple Silicon.
Для другой системы замените значение `asset` по таблице.

```sh
version=v0.4.0
asset=secscan-darwin-arm64
release="https://github.com/sagolubev/secscan/releases/download/$version"
curl -fL "$release/$asset" -o "$asset"
curl -fL "$release/SHA256SUMS" -o SHA256SUMS
```

Проверьте SHA256 выбранного файла. На macOS:

```sh
awk -v file="$asset" '$2 == file' SHA256SUMS | shasum -a 256 -c -
```

На Linux:

```sh
awk -v file="$asset" '$2 == file' SHA256SUMS | sha256sum -c -
```

После результата `OK` установите файл в пользовательский каталог:

```sh
mkdir -p "$HOME/.local/bin"
install -m 755 "$asset" "$HOME/.local/bin/secscan"
export PATH="$HOME/.local/bin:$PATH"
secscan --version
```

Добавьте строку `export PATH=...` в `~/.zshrc` или `~/.bashrc`, чтобы команда
была доступна в новых терминалах. Ожидаемый вывод версии: `secscan v0.4.0`.

`secscan --licenses` показывает лицензию и сведения о сторонних компонентах.
Оба информационных флага работают без Git-репозитория и Docker.

</details>

## Первый запуск

Запустите Docker и проверьте соединение командой `docker info`.
На macOS каталог репозитория и пользовательский кэш должны быть доступны
виртуальной машине Docker/Colima через общий доступ к файлам.
Затем подготовьте сканеры для своего репозитория:

```sh
secscan update /path/to/repository
secscan /path/to/repository > /tmp/secscan-report.json
```

Замените `/path/to/repository` своим путём. Без пути secscan использует текущий
каталог. Путь к подкаталогу также выбирает весь содержащий его Git-репозиторий.
Все флаги указываются перед путём.

`update` скачивает закреплённые версии движков и базы уязвимостей.
Первая подготовка может занять несколько минут и несколько гигабайт.
Файлы хранятся в пользовательском кэше, вне проверяемого репозитория.
Они не входят в скачанный бинарник.

Обычное сканирование ничего не скачивает. Если база отсутствует, повреждена или
старше пяти суток, повторите `update`. Этот срок относится к базам уязвимостей.
Статические правила проверяются по версии и хешу.

Отчёт сохраняйте вне проверяемого репозитория, чтобы сканеры не читали его
во время записи. Прогресс и ошибки идут в stderr, JSON — в stdout.

## Docker, Podman и rootless

Поддержка namespace ниже относится к текущим исходникам и войдёт в следующий
бинарный релиз. Secscan сначала ищет Docker, затем Podman. Чтобы явно выбрать
backend, задайте переменную для обеих команд:

```sh
SECSCAN_RUNTIME=podman secscan update /path/to/repository
SECSCAN_RUNTIME=podman secscan /path/to/repository > /tmp/secscan-report.json
```

Допустимы только `docker` и `podman`. При явном выборе secscan не переключается
на другой backend. Для Docker можно использовать обычный `DOCKER_HOST` или
текущий Docker context, включая socket rootless-демона. Сам daemon должен уже
работать: secscan не меняет настройки Docker, systemd, users или namespaces.

Для Docker rootless/userns-remap и Podman rootless входы передаются в отдельные
временные тома. Scanner сохраняет numeric user, отключённые capabilities,
`no-new-privileges` и read-only inputs. Исходные права файлов не меняются.
Выходные файлы и новые поколения кэша возвращаются с владельцем текущего
пользователя. После запуска тома и контейнеры удаляются; при ошибке очистки
scan не считается успешным. Сеть по-прежнему разрешается только для явных
операций подготовки и загрузки образов.

Проверены Docker 29.5.2 с rootless/systemd и userns-remap, а также
Podman 4.9.3 rootless/cgroupfs на Linux arm64. CI отдельно проверяет все три
режима на Linux amd64. Для namespace-переноса действует лимит 8 GiB и
100000 entries на mount. Symlinks и специальные файлы не переносятся.
Сканеры получают уже отобранные временные деревья, а базы — проверенные
поколения кэша; превышение лимита даёт явную ошибку.

## Выбор проверок

По умолчанию запускаются 17 проверок. Проверка образов включается отдельно.
Сканер без подходящих входных файлов получает статус `skipped`.

| Область | Значения `--scanners` |
|---|---|
| Секреты в рабочем дереве | `gitleaks` |
| Секреты в истории Git, по явному выбору | `gitleaks-history` |
| Код | `python-sast`, `typescript-sast`, `semgrep`, `bearer`, `cppcheck` |
| Зависимости | `trivy`, `grype`, `osv-scanner` |
| CI | `zizmor`, `poutine` |
| Инфраструктура | `checkov`, `checkov-terraform`, `kics` |
| Gradle | `gradle-catalog`, `gradle-scripts`, `refresh-versions` |
| Образы контейнеров | `oci-images` |

Например, только Python и TypeScript:

```sh
secscan update --scanners python-sast,typescript-sast /path/to/repository
secscan --scanners python-sast,typescript-sast /path/to/repository > /tmp/secscan-code.json
```

Для проверки образов из Dockerfile, Kubernetes и Compose:

```sh
secscan update --scanners oci-images /path/to/repository
secscan --scanners oci-images --scan-images /path/to/repository > /tmp/secscan-images.json
```

`--scan-images` разрешает Docker скачать отсутствующие целевые образы.
Secscan экспортирует их для Trivy и Grype, но не запускает.
После проверки он удаляет только образы, которые загрузил сам.
Уже существовавшие образы сохраняются.

## Дополнительные правила

Эти команды доступны в сборке из текущих исходников и войдут в следующий
бинарный релиз. Пакет выбирается явно; secscan не загружает его из сети.

Создайте каталог с `rules.toml`, YAML-правилами и текстом их лицензии.
Пример `rules.toml` для собственных правил:

```toml
version = 1
source = "local"
license = "MIT"
license_file = "LICENSE"
files = ["custom.yml"]
```

Для внешних правил укажите в `source` HTTPS-адрес без credentials, query и
fragment; необязательный `revision` хранит полный commit SHA. Secscan сохраняет
заявленную лицензию и её текст. Право использования проверяет владелец пакета.

Пример `custom.yml`:

```yaml
rules:
  - id: python-unsafe-pickle
    languages: [python]
    message: Untrusted pickle deserialization
    severity: ERROR
    pattern: pickle.loads($VALUE)
```

Импортируйте каталог и скопируйте поле `id` из JSON-ответа:

```sh
secscan rules import /path/to/my-rules
secscan rules show <id>
secscan --rule-pack <id> --scanners python-sast,semgrep /path/to/repository
```

ID — SHA-256 всего пакета, включая источник, лицензию и точные YAML bytes.
Повторный импорт тех же данных возвращает тот же ID. Scan проверяет кэш и
материализует собственную копию правил; сеть контейнеров выключена.
Для возврата к прежним правилам выберите старый ID или уберите `--rule-pack`.
Встроенные правила сохраняются. `--rule-pack` недоступен для `update`.

Пакеты работают с Semgrep и отдельными Python/TypeScript jobs. Для Semgrep
добавляются исходники языков, явно указанных в пакете; `--scope` также применяется.
Допустимые language tags: `python`, `javascript`, `typescript`, `go`, `java`,
`ruby`, `php`, `c`, `cpp`, `csharp`, `kotlin`, `rust`, `swift`, `scala`, `lua`,
`bash`, `html`, `css`. Алиасы и `generic` не принимаются. Полную совместимость
DSL проверяет выбранный движок при scan; ошибочные правила не пропускаются молча.

В `scanners[].customRulePack` записаны ID, source, license, revision и число
custom rules. `rulePackDigest` описывает выбранный набор, `ruleCount` включает
встроенные правила. Эти сведения также сохраняются в HTML и SARIF.
Custom finding IDs содержат полный pack ID. Динамические messages и metavariables
не выводятся: сообщение находки — `custom rule matched`.

Limits: 256 YAML files, 4096 rules, 2 MiB на файл и 16 MiB на пакет;
manifest и license — до 64 KiB каждый. Symlinks, duplicate keys/IDs, YAML aliases,
remote includes и executable validators отклоняются. Кэш должен находиться
вне сканируемого репозитория. Наборы сторонних правил не входят в бинарник.

## История Git

В текущих исходниках доступен отдельный scanner `gitleaks-history`.
Он не входит в `all`. Подготовьте движок и явно выберите историю:

```sh
secscan update --scanners gitleaks-history /path/to/repository
secscan --scanners gitleaks,gitleaks-history /path/to/repository > /tmp/secscan-history.json
```

Проверяется история, достижимая из текущего `HEAD`, включая удалённые файлы.
Это не обход всех branches/tags. Для другой ветки выберите её checkout или linked
worktree. Находки истории имеют `origin: git_history` и полный `commit` SHA;
текущее дерево сохраняет `origin: working_tree`. Commit входит в fingerprint,
показывается в HTML и сохраняется в SARIF и baseline. Исторические секреты
остаются `exempt` при сравнении baseline.

`scanners[].history.head` фиксирует выбранный HEAD, `history.commits` считает
reachable candidates. Gitleaks проверяет добавленные строки patch history и
сообщает завершение на уровне репозитория; число кандидатов не является
подтверждением анализа каждого commit.

Scanner получает самостоятельный bare snapshot с read-only mount и отключённой
сетью. Исходные `.git`, config, hooks и shared common directory в контейнер
не передаются. Ошибки Git не считаются успешным scan даже при exit code 0.
Source Git state не меняется; временный snapshot удаляется после запуска.

Shallow repositories, grafts, изменившийся при snapshot HEAD, более 100000 commits
или bundle больше 512 MiB дают ошибку вместо молчаливого усечения. `--scope`
несовместим с history scanner. Native inline waivers Gitleaks сохраняются.

## Отдельные файлы и каталоги

`--scope` выбирает файл или каталог относительно корня Git-репозитория:

```sh
secscan --scope src --scope scripts/check.py \
  --scanners gitleaks,python-sast,typescript-sast \
  /path/to/repository > /tmp/secscan-scoped.json
```

Можно передать до 16 scopes. Пересечения не дублируют файлы. Используйте имена
в том написании, в котором они находятся в Git inventory. `.` выбирает все
eligible files. Абсолютные пути, `..`, symlinks, отсутствующие пути и scope
без подходящих nonignored regular files дают ошибку.

Gitleaks, Python/TypeScript, Semgrep и Zizmor получают только выбранные входы.
Остальные сканеры сохраняют полный контекст репозитория. Например, Trivy может
вернуть finding из lockfile вне выбранного каталога — её путь не меняется.

`scope.paths` и `scope.selectedFiles` описывают выбор. В `scanners[].scope`
поле `mode` равно `files` или `repository`, а `candidateFiles` считает входные
кандидаты. Это не подтверждение чтения: его по-прежнему показывает coverage.
Inventory описывает всё рабочее дерево. HTML и SARIF сохраняют эти границы.

Scopes несовместимы с `update`, `--baseline` и `--write-baseline`; эти сочетания
дают exit code `2`. Project-фильтры можно применять к scoped scan обычным способом.

## Dependency-Track и SonarQube

Начиная с v0.2.0, secscan может сохранить два отчёта из одного запуска Trivy:

```sh
secscan update --scanners trivy /path/to/repository
secscan --scanners trivy --trivy-reports /tmp/secscan-trivy \
  /path/to/repository > /tmp/secscan-report.json
```

Каталог `/tmp/secscan-trivy` должен быть новым и находиться вне проверяемого
репозитория. Его родительский каталог должен существовать. Для повторного
запуска выберите новое имя: secscan не перезаписывает прежние отчёты.

| Файл | Назначение |
|---|---|
| `trivy.cdx.json` | CycloneDX 1.6 SBOM для Dependency-Track 4.12+ |
| `trivy.sonarqube.json` | Внешние замечания для SonarQube Server 10.3+ |

В Dependency-Track откройте проект и загрузите `trivy.cdx.json` как BOM.
Файл содержит все обнаруженные Trivy пакеты, включая пакеты без уязвимостей.
Dependency-Track анализирует их своими источниками данных, поэтому его находки
могут отличаться от Trivy. Связи зависимостей сохраняются, если Trivy их сообщил.

Для SonarQube добавьте property к своему обычному запуску SonarScanner из
корня проверяемого репозитория:

```sh
sonar-scanner \
  -Dsonar.externalIssuesReportPaths=/tmp/secscan-trivy/trivy.sonarqube.json
```

Настройки проекта и аутентификации SonarScanner остаются вашими.
Manifest и lockfiles из замечаний должны входить в индекс SonarScanner.
Проверьте число импортированных замечаний в его логе: исключённые файлы
SonarQube пропускает. Замечания привязаны к файлу целиком, без выдуманных строк.

Экспорт содержит только зависимости репозитория, прочитанные Trivy.
Он не включает OCI-образы и результаты других сканеров. Это не SARIF.
Если Trivy завершился ошибкой, пропущен или оставил unread/failed inputs,
secscan возвращает `1` и не публикует эти файлы. Доступный обычный JSON
остаётся в stdout. Полный успешный анализ без уязвимостей создаёт SBOM и
пустой список замечаний SonarQube.

В SonarQube Server 2025.1+ для Standard Experience уровни Trivy
critical/high/medium/low/unknown соответствуют BLOCKER/CRITICAL/MAJOR/MINOR/INFO.
Для MQR используются SECURITY impacts HIGH/HIGH/MEDIUM/LOW/LOW.
Старые версии, включая 10.3 и 10.7, выводят Standard severity из impacts:
critical/high и low/unknown в них объединяются. Неизвестная severity явно
указана в сообщении. Secscan сам ничего не загружает в сервисы и не запрашивает токены.
[Форматы и ограничения импорта](docs/trivy-export-formats.md).

## HTML и SARIF

Можно сохранить отчёт для браузера и полный SARIF за один scan:

```sh
secscan --html /tmp/secscan-report.html --sarif /tmp/secscan-report.sarif \
  /path/to/repository > /tmp/secscan-report.json
```

HTML открывается локально, без сети и JavaScript. В нём видны находки,
статусы сканеров, пробелы покрытия и inventory. Поиск и печать работают
обычными средствами браузера. Текст репозитория и сообщений экранируется.

SARIF 2.1.0 содержит все нормализованные находки, их fingerprints, package и
advisory metadata. Ограничения анализа сохраняются в свойствах run и
notifications. При `--baseline` JSON и HTML показывают результат сравнения,
а SARIF сохраняет полный scan. Trivy integration exports также остаются полными.

Файлы назначения должны быть новыми, а их родительские каталоги — существовать.
Существующие файлы и symlinks не заменяются. Явно указанные output-файлы внутри
worktree исключаются из scan. Для обычного перенаправления stdout через `>`
по-прежнему выбирайте файл вне репозитория.

Каждый файл публикуется целиком. Несколько output-файлов не являются одной
транзакцией: если поздняя запись не удалась, уже созданный полный файл остаётся.
Ошибка экспорта даёт exit code `1` и сохраняет JSON stdout. Если начавшийся scan
завершился ошибкой, HTML/SARIF сохраняют доступный report с failed coverage;
код завершения остаётся `1`. Флаги недоступны для `update`.

## Ограничение размера JSON

В сборке из текущих исходников `--max-tokens` сокращает только JSON в stdout:

```sh
secscan --max-tokens 16000 --sarif /tmp/secscan-full.sarif \
  /path/to/repository > /tmp/secscan-small.json
```

Счётчик `utf8-bytes-v1` считает один UTF-8 byte за одну единицу budget.
Он включает весь JSON, собственные metadata и завершающий перевод строки.
Это консервативный лимит, а не точное число токенов конкретной модели;
он может убрать больше находок, чем её tokenizer. Без флага сокращения нет.

Secscan удаляет целые группы severity от informational к critical, пока JSON
не поместится. Секреты, ошибки, неизвестная severity и сведения о покрытии
сохраняются. `budget.floor` показывает выбранный порог, `removedFragments`
и `retainedFragments` — число убранных и оставшихся фрагментов после обычных
фильтров. `budget.measured` содержит фактический размер в выбранных единицах.

Если обязательные данные сами превышают лимит, secscan сохраняет их целиком,
добавляет `budget.exceeded: true` и пишет предупреждение в stderr. При соблюдении
лимита поле `exceeded` отсутствует. Код завершения
по-прежнему зависит от результата scan. Значение должно быть положительным
целым числом; `update` этот флаг не принимает.

HTML сохраняет обычный видимый отчёт. SARIF, новый baseline и Trivy-экспорты
остаются полными. Их содержимое от `--max-tokens` не меняется.

## Как читать результат

При наличии `jq` можно посмотреть статусы сканеров:

```sh
jq '.scanners[] | {name, status, coverage, limitations}' /tmp/secscan-report.json
```

И отдельно находки:

```sh
jq '.findings[] | {kind, severity, ruleId, path, line, sources}' /tmp/secscan-report.json
```

Отсутствие находок не означает, что все файлы проверены. Смотрите `status`,
`coverage.read`, `coverage.failed`, `unreadInputs`, `failedInputs` и `limitations`.
Значения секретов и фрагменты исходного кода в отчёт не попадают.

`inventory` отделяет eligible tracked/untracked файлы от ignored и omitted.
В каждой группе есть число файлов, байты и счётчики по каталогам.
Строка каталога считает только его непосредственные файлы, без вложенных,
поэтому суммы не дублируются. Symlinks, исчезнувшие и non-regular inputs
перечислены с причиной. `unclassified` содержит файлы без известной категории.
Это учёт входов, а не доказательство анализа.

`uncheckedInputs` перечисляет известные code/dependency inputs без подходящего
сканера, без выбранной проверки или без положительного read evidence.
Проверка секретов не считается SAST/SCA. Gitleaks получает тот же набор
nonignored regular files, но сообщает завершение на уровне репозитория.
Python/TypeScript считают только пути, подтверждённые Opengrep.

```sh
jq '{inventory, uncheckedInputs}' /tmp/secscan-report.json
```

| Код завершения | Значение |
|---|---|
| `0` | Хотя бы один сканер успешен, либо все выбранные проверки пропущены из-за отсутствия подходящих файлов |
| `1` | Запуск не состоялся, все запущенные сканеры завершились ошибкой или запрошенный экспорт не выполнен |
| `2` | Неверные аргументы |

Сами находки не меняют код завершения. При частичном сбое отчёт сохраняет
доступные результаты и статусы ошибок. Ошибка до начала сканирования, например
недоступный Docker, не создаёт отчёт.

В терминале `--progress auto` показывает таблицу прогресса. Для CI используйте
`--progress plain`, для отключения прогресса — `--progress off`.
`NO_COLOR=1` отключает цвет. Полосы показывают прошедшее время, а не процент
готовности. В маленьком окне вывод переключается на строки событий.

## Сравнение с предыдущим сканом

Сохраните полные находки в новый baseline-файл:

```sh
secscan --write-baseline /tmp/secscan-baseline.json /path/to/repository
```

После изменений выполните scan с этим baseline:

```sh
secscan --baseline /tmp/secscan-baseline.json /path/to/repository > /tmp/secscan-new.json
```

В `findings` остаются новые находки (`baselineStatus: new`), новые места или
advisory IDs известных проблем (`expanded`) и все секреты/ошибки (`exempt`).
Повышение severity также остаётся видимым. Поле `baseline` содержит счётчики
исходных находок и выходных фрагментов. Одна проблема может дать два фрагмента,
если одновременно появились новые locations и advisory IDs.

Coverage и inventory сохраняются: пустой список новых находок не доказывает
полноту анализа. Baseline не сообщает, что исчезнувшая finding исправлена.
Trivy SBOM и SonarQube exports при этом получают полный результат scan.

Файл baseline можно хранить внутри worktree: выбранный control file исключается
из scanner inputs и указывается в `inventory.omitted`. Для CI используйте
baseline из доверенного предыдущего запуска. Изменённый в PR baseline не должен
сам определять, какие проблемы этого PR считать известными.

`--write-baseline` создаёт новый файл и не перезаписывает существующий.
Флаги записи и сравнения взаимоисключаются и не работают с `update`.
При failed scanner запись отклоняется. Ожидаемые skipped/unread inputs остаются
видны в обычном отчёте; snapshot хранит наблюдавшиеся находки, не аттестацию покрытия.
Неподдерживаемая schema, fingerprint algorithm или файл больше 32 MiB дают ошибку.
Для новой версии baseline выберите новое имя файла. Это пользовательское сравнение
сканов, отдельное от фазового baseline в GRACE-проверках разработки.

## Исключения и порог severity

Secscan читает `.secscan.toml` из корня Git-репозитория перед сканированием.
Файл необязателен. Например:

```toml
version = 1
min_severity = "medium"
test_paths = ["testdata/"]

[[suppressions]]
id = "fixture-eval"
reason = "Тестовый пример намеренно вызывает eval"
rule = "secscan.python.dynamic-code-execution"
path = "tests/"
```

У suppression обязательны уникальный `id`, непустой `reason` и хотя бы один
селектор: `kind`, `rule`, `fingerprint`, `path` или `advisory`. Все заданные
селекторы должны совпасть. Rule, fingerprint и advisory сравниваются точно.
`path` принимает относительный путь, маску `*`, `?`, `[...]` или буквальный
префикс каталога с завершающим `/`. `**`, абсолютные пути и `..` запрещены.

Выбор другого файла, отключение project policy и переопределение порога:

```sh
secscan --config /path/to/policy.toml /path/to/repository
secscan --no-config /path/to/repository
secscan --min-severity high /path/to/repository
```

`--config` и `--no-config` взаимоисключаются. Эти флаги и `--min-severity`
недоступны для `update`. CLI-порог заменяет `min_severity` из файла.
Уровни: `informational`, `low`, `medium`, `high`, `critical`.
Неизвестная severity остаётся видимой при любом пороге. Находки `secret` и
`error` сохраняются при всех project-фильтрах, включая baseline и test-data.

Порядок обработки: inline waivers самого scanner → project rules по порядку
в файле → baseline → severity floor → `test_paths`. Исключения внешнего движка
не имеют сводных counts: scanner не передаёт скрытые им находки. Для CI можно
передать проверенную внешнюю policy через `--config` или отключить project policy.

`filtering` в JSON и HTML показывает исходное число findings, итоговое число
фрагментов и удалённые элементы каждого этапа. `occurrences` считает сочетания
advisory/location; для кода — locations. Place или advisory считается удалённым,
только когда его нет ни в одном оставшемся фрагменте. Пересекающиеся правила
не считают одно удаление дважды. При частичном исключении fingerprint сохраняется.
После такого разделения baseline counts относятся к фрагментам на входе его этапа.

JSON и HTML содержат видимый результат. SARIF, Trivy-экспорты и новый baseline
сохраняют полный scan. Coverage и inventory фильтры не изменяют. Поле `reason`
остаётся в конфигурации и не переносится в отчёт; выбранный config исключается
из scanner inputs.

Config должен быть обычным UTF-8 файлом размером до 1 MiB, с `version = 1`
и не более 256 правил. ID — до 64 ASCII букв, цифр и символов `._-`, reason —
до 1024 байт. Symlink, неизвестный ключ, неверный тип, повторный ID или
некорректный селектор дают ошибку до scan. Регистр имён ключей значим.

## Что пока ограничено

По умолчанию Python, TypeScript и Semgrep используют собственный набор из восьми правил.
Это не полный набор правил Semgrep. Bearer работает только на native amd64.
Его результат подтверждает чтение лишь файлов с находками. Остальные остаются
непрочитанными в отчёте. Cppcheck проверяет C/C++ без сборки проекта.

Gradle-проверки читают статические координаты зависимостей, не запускают wrapper
или build scripts. `refresh-versions` читает существующие подсказки обновлений,
но не проверяет доступность новых версий. GitLab includes не загружаются.
Обычный `gitleaks` проверяет рабочее дерево; `gitleaks-history` выбирается отдельно.

LLM-анализ отложен. [Историческое сравнение с DietSec](docs/feature-status.md)
описывает commit `c406ed3` от 6 сентября 2026 года. Текущие возможности описаны
выше, актуальный остаток требований и задачи находятся в OpenSpec и Beads.

## Разработка

Для изменения кода нужен Go 1.24 или новее. Клонируйте репозиторий и выполните
проверки из его корня:

```sh
git clone https://github.com/sagolubev/secscan.git
cd secscan
go build -o /tmp/secscan-dev ./cmd/secscan
bash .github/scripts/check.sh
```

Последняя команда проверяет форматирование, зависимости, `go vet` и тесты с
race detector. Для реальных контейнерных проверок нужен работающий Docker.
Сначала скачайте закреплённый образ для runtime-тестов:

```sh
docker pull ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
SECSCAN_ACCEPTANCE=1 SECSCAN_BEARER_ACCEPTANCE=1 \
  go test ./... -run TestAcceptance -count=1 -timeout=35m
```

Bearer acceptance пропускается на arm64. CI выполняет проверки Go на Linux и
macOS, контейнерные тесты на Linux amd64/arm64 и сборки для всех четырёх платформ.
Тег `vMAJOR.MINOR.PATCH` публикует бинарники только после успешных проверок.

Сборка из текущих исходников также проверяет OS и архитектуру самого container
server, включая remote Docker/Podman. Движкам нужен Linux amd64/arm64; Bearer —
Linux amd64. Несовместимый scanner получает `skipped`, нулевой read и причину
`unsupported_runtime_os` или `unsupported_runtime_arch`. Остальные проверки,
включая нативный `refresh-versions`, продолжаются. Эмуляция не включается.
`update` готовит совместимые движки; если совместимых нет, сохраняет прежний
cache manifest и возвращает ошибку.

Требования и сценарии находятся в [OpenSpec](openspec/changes/build-secscan/specs/secscan/spec.md),
задачи и результаты проверок — в Beads (`br`). Для работы с ними нужны
[OpenSpec 1.12.0](https://github.com/Fission-AI/OpenSpec) и
[br 0.2.19](https://github.com/Dicklesworthstone/beads_rust/releases/tag/v0.2.19).

Перед изменением прочитайте [AGENTS.md](AGENTS.md), связанную задачу и design.
В ключевых Go-файлах есть GRACE contract/map: назначение, ограничения, символы
и ссылки на тесты. [Правила навигации](docs/code-navigation.md) объясняют разметку.
До реализации, включая новые тесты, задайте в
[trace.json](openspec/changes/build-secscan/trace.json) задачу `targetOutcome`,
полный исходный commit SHA в `baselineCommit`, ожидаемые файлы `scope` и checks.
Поддерживайте ссылки requirement → component → test. Снимите исходный baseline:

```sh
openspec validate --all --strict
go run ./cmd/tracecheck --phase baseline --run
```

Затем получите падающий тест, внесите изменение и проведите независимое review.
Добавьте проверенные файлы в index через `git add` и выполните:

```sh
go run ./cmd/tracecheck --phase target --run
go run ./cmd/tracecheck --phase final --run
go run ./cmd/tracecheck --verify-evidence
```

Каждая фаза сохраняет полный результат в Beads. Последняя команда проверяет
сохранённую цепочку и её соответствие текущему коду; сканеры повторно не запускает.
Перед закрытием задачи через `br close` эта проверка должна пройти.
Manifest и команды остаются теми же между фазами. Новый scope или набор checks
требует нового спланированного outcome.

Для быстрой сверки используйте `go run ./cmd/tracecheck --validate-only`.
Он проверяет ссылки, Go-карты, полный diff, состояние требований и задач.
Он не запускает сценарии и не заменяет фазовый evidence.
Поле `target` означает наличие связи с кодом и тестом, `deferred` — отложенный
сценарий. Независимое review проверяет смысл этих связей.

При наличии `jq` список отложенных сценариев можно получить из manifest:

```sh
jq -r '.traces[] | select(.disposition == "deferred") |
  [.requirement, .scenario, .issue] | @tsv' \
  openspec/changes/build-secscan/trace.json
```

Команды фаз `baseline`, `target` и `final` заданы в `trace.json`.
Для полного запуска фаз дополнительно нужны `actionlint` и `opsx-stale` из
принятого workflow. `br sync --flush-only` сохраняет комментарии с evidence
в `.beads/issues.jsonl` для commit. CI проверяет сохранённую цепочку, разметку,
экспорт/импорт Beads и запускает свежие тесты. Старые legacy-записи не заменяют
новый baseline. Ограничения Git и порядок фаз описаны в
[руководстве GRACE](docs/grace-integration.md).

[Оценка пилота GRACE](docs/grace-pilot.md) описывает опыт проекта.
[Разбор исходного GRACE](docs/grace-integration.md) объясняет, что можно
автоматизировать вместе с OpenSpec, Beads и TDD.
