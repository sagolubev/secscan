# Secscan

Go CLI для локального AppSec-анализа Git worktree. Запускает scanners в
изолированных контейнерах и объединяет результаты в JSON schema v1.

Из каталога secscan:

```sh
go run ./cmd/secscan update /path/to/repository
go run ./cmd/secscan --progress auto /path/to/repository
```

Для отдельного бинарника: `go build -o /tmp/secscan ./cmd/secscan`.
Нужен Go 1.24+ и работающий Docker или Podman. Реальные acceptance tests
выполнены на Docker/Colima arm64; Podman и rootless здесь не проверялись.

`update` загружает закреплённые images, собирает project-owned images и
атомарно публикует необходимые базы в user cache. Первая подготовка может
занять несколько минут и несколько GiB. Обычный scan ничего не скачивает;
отсутствующие, повреждённые или просроченные базы дают failed coverage.
Advisory snapshots действуют пять суток. Статические rules проверяются по
version и digest, без этого срока годности.

| Область | Personas |
|---|---|
| Secrets | `gitleaks` |
| Code | `python-sast`, `typescript-sast`, `semgrep`, `bearer`, `cppcheck` |
| Dependencies | `trivy`, `grype`, `osv-scanner` |
| CI | `zizmor`, `poutine` |
| IaC | `checkov`, `checkov-terraform`, `kics` |
| Gradle | `gradle-catalog`, `gradle-scripts`, `refresh-versions` |
| Container images | `oci-images` — только с `--scan-images` |

По умолчанию выбраны все 17 personas без анализа container images.
Для выбора подмножества: `--scanners python-sast,typescript-sast,trivy`.
Обнаруженные OCI references без разрешения остаются unchecked.

```sh
go run ./cmd/secscan update --scanners oci-images /path/to/repository
go run ./cmd/secscan --scanners oci-images --scan-images /path/to/repository
```

`--scan-images` разрешает host runtime загрузить отсутствующие target images
и экспортировать их в archives. Target images не запускаются; scanners не
получают runtime socket. Существовавшие images сохраняются, загруженные этим
run удаляются. Digest, engine/feed metadata и состояние cleanup входят в report.

Progress идёт в stderr: `auto`, `tty`, `plain` или `off`. В TTY видны stages,
elapsed bars и findings каждого scanner. Журнал сокращается под высоту окна;
в слишком маленьком окне используется plain progress. `NO_COLOR` отключает цвет.
Stdout содержит JSON. При ошибке доступный частичный report сохраняется с
failed statuses; диагностика остаётся в stderr. Exit codes: `0` — успешный
анализ либо только skipped personas, `1` — ошибка без успешного scanner,
`2` — неверные аргументы. Сами findings не меняют exit code.

Проверяйте `coverage`, `unreadInputs`, `failedInputs` и `limitations`, а не
только число findings. Python/TypeScript и Semgrep используют собственные восемь
MIT rules. Bearer пропускается на ARM64; native amd64 run здесь не проверялся.
Его SARIF подтверждает только paths с findings: остальные inputs остаются
unread, пустой неподтверждённый результат даёт failure. Bearer rules и upstream
images используются через private cache, без redistribution.

Gradle-анализ извлекает только статические coordinates. Wrappers, plugins и
build scripts не выполняются. Dynamic expressions остаются unread.
`refresh-versions` читает существующие update hints и не подтверждает текущую
доступность версий или отсутствие vulnerabilities. GitLab includes также
остаются unread. OpenTofu suffixes адаптируются только в staged-копии;
конфликт `.tf`/`.tofu` одного имени даёт ошибку.

OpenSpec хранит требования и design; Beads (`br`) — задачи и evidence.
`openspec/changes/build-secscan/trace.json` связывает requirements с components
и tests, проверяет полный diff scope и формирует baseline/target/final evidence.

```sh
gofmt -d .
go vet ./...
go test ./...
SECSCAN_ACCEPTANCE=1 go test ./... -run TestAcceptance -count=1 -timeout=30m
go run ./cmd/tracecheck --phase final --run
```
