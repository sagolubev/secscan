# Secscan

[Скачать](https://github.com/sagolubev/secscan/releases/latest) · [MIT](LICENSE) · [CI](https://github.com/sagolubev/secscan/actions/workflows/ci.yml)

Secscan запускает проверки безопасности локального Git-репозитория и собирает
находки в один JSON-отчёт. Он проверяет секреты, код, зависимости, CI и
инфраструктурные файлы. Во время запуска в терминале виден прогресс каждого сканера.

Для работы нужен один бинарник, Git и запущенный Docker. Поддержка Podman есть
в коде, но пока не подтверждена acceptance-тестами. Go, Python и Node.js на
компьютере пользователя не нужны: внешние сканеры работают в контейнерах.

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
  sh -s -- --version v0.2.0 --dir "$HOME/.local/bin"
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

В [релизе v0.2.0](https://github.com/sagolubev/secscan/releases/tag/v0.2.0)
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
version=v0.2.0
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
была доступна в новых терминалах. Ожидаемый вывод версии: `secscan v0.2.0`.

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

## Выбор проверок

По умолчанию запускаются 17 проверок. Проверка образов включается отдельно.
Сканер без подходящих входных файлов получает статус `skipped`.

| Область | Значения `--scanners` |
|---|---|
| Секреты в рабочем дереве | `gitleaks` |
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

## Что пока ограничено

Python, TypeScript и Semgrep используют один собственный набор из восьми правил.
Это не полный набор правил Semgrep. Bearer работает только на native amd64.
Его результат подтверждает чтение лишь файлов с находками. Остальные остаются
непрочитанными в отчёте. Cppcheck проверяет C/C++ без сборки проекта.

Gradle-проверки читают статические координаты зависимостей, не запускают wrapper
или build scripts. `refresh-versions` читает существующие подсказки обновлений,
но не проверяет доступность новых версий. GitLab includes не загружаются.
Gitleaks проверяет рабочее дерево, а не историю Git.

Пока нет HTML/SARIF-экспорта, baseline-сравнения, пользовательских исключений,
сканирования выбранных файлов и LLM-анализа. Podman и rootless остаются
непроверенными режимами. Подробности, оставшиеся требования и сравнение с
DietSec собраны в [обзоре возможностей](docs/feature-status.md).

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

Требования и сценарии находятся в [OpenSpec](openspec/changes/build-secscan/specs/secscan/spec.md),
задачи и результаты проверок — в Beads (`br`). Для работы с ними нужны
[OpenSpec 1.12.0](https://github.com/Fission-AI/OpenSpec) и
[br 0.2.19](https://github.com/Dicklesworthstone/beads_rust/releases/tag/v0.2.19).

Перед изменением прочитайте [AGENTS.md](AGENTS.md), связанную задачу и design.
В ключевых Go-файлах есть GRACE contract/map: назначение, ограничения, символы
и ссылки на тесты. [Правила навигации](docs/code-navigation.md) объясняют разметку.
Для нового поведения сначала получите падающий тест, затем внесите изменение.
До реализации задайте в [trace.json](openspec/changes/build-secscan/trace.json)
задачу `targetOutcome`, исходный `baselineCommit` и ожидаемые файлы `scope`.
Поддерживайте ссылки requirement → component → test и проверяйте их:

```sh
openspec validate --all --strict
go run ./cmd/tracecheck --validate-only
br list --all
```

`--validate-only` проверяет ссылки, scope, состояние требований и задач.
Он не запускает сценарии и не доказывает выполнение всех требований.
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
принятого workflow. Evidence хранится в Beads. Перед закрытием задачи
сопоставьте её требования, фактический diff, результаты тестов и review.

[Оценка пилота GRACE](docs/grace-pilot.md) описывает опыт проекта.
[Разбор исходного GRACE](docs/grace-integration.md) объясняет, что можно
автоматизировать вместе с OpenSpec, Beads и TDD.
