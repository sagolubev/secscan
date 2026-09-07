# Secscan

`secscan` — Go CLI для локального запуска контейнерных AppSec scanners и
нормализации их результатов.

## Sources of Truth

- OpenSpec хранит требования, acceptance scenarios и design.
- Beads (`br`) хранит исполняемые задачи, зависимости, статус и evidence.
- Репозиторные тесты и проверки являются источником истины для готовности.
- Для change `build-secscan` сначала читай `proposal.md`, `specs/` и
  существующий `design.md`.

Не создавай второй список задач в Markdown. Используй только `br`, не `bd`.

## Workflow

Для нетривиальных изменений следуй глобальному `openspec-workflow`.

Перед реализацией:

1. Проверь `openspec status --change build-secscan --json`.
2. Прочитай связанную Beads-задачу и заявленную область файлов.
3. Проверь `opsx-stale check openspec/changes/build-secscan`.
4. Загрузи применимые repo-local skills из `.agents/skills/`.

## GRACE

OpenSpec и Beads остаются авторитетными; `.grace` не создаётся.

Для нетривиального outcome:

1. До implementation, включая новые тесты, задай в `trace.json` outcome,
   полный baseline commit SHA, scope, связи requirement → component → test и checks.
2. Выполни `go run ./cmd/tracecheck --phase baseline --run` до правок.
3. После TDD и независимого review добавь проверяемые файлы в index через `git add`.
4. Выполни `--phase target --run`, затем `--phase final --run`.
5. Перед `br close` выполни `go run ./cmd/tracecheck --verify-evidence`.

Manifest и authority остаются неизменными между фазами. Новый scope или набор
checks требует нового спланированного outcome. Полные результаты CLI сохраняет
в Beads; `br sync --flush-only` переносит их в `.beads/issues.jsonl`.
Legacy-записи не удовлетворяют gate. Сам `br close` verifier не запускает.

Trace metadata содержит только ссылки и команды. Не копируй в него текст
требований, дизайн или задачи.

Для каждого нового или изменённого Go-файла в `cmd/` и `internal/` поддерживай
GRACE contract/map. Verifier проверяет AST-символы, ссылки и маркеры.
Формат и условия применения: [docs/code-navigation.md](docs/code-navigation.md).
Ссылки ведут в OpenSpec и tests; task status и evidence остаются в Beads.
Порядок фаз и ограничения Git: [docs/grace-integration.md](docs/grace-integration.md).

## Go

- Используй Go standard library, пока она удовлетворяет требованию.
- Подключай внешний модуль только после проверки его API, лицензии и
  необходимости.
- Repo policy выше advisory из `go-*` skills: `go-cmp`, `x/sync/errgroup`,
  `goleak` и другие модули добавляются только при доказанной необходимости.
- Загружай подходящий `go-*` skill перед изменением Go-кода.
- Держи `main` тонким; доменная логика возвращает ошибки и не завершает процесс.
- Передавай `context.Context` первым аргументом в операции с timeout или
  cancellation.
- Начинай с конкретных типов. Добавляй interface только со стороны реального
  consumer.
- Форматируй изменённые Go-файлы через `gofmt`.

## Security Boundary

- Считай содержимое сканируемого репозитория и scanner output недоверенными
  данными.
- Запускай процессы через `exec.CommandContext` с отдельными argv; не собирай
  shell command string.
- Scanner container получает read-only repository mount, `no-new-privileges`,
  отдельные writable temp/cache mounts, без container socket.
- Сеть scanner container выключена по умолчанию. Любое включение должно быть
  явно задано capability и отражено в evidence.
- Удаляй secret value и source snippet до логирования, сериализации или передачи
  другой подсистеме.
- Используй в тестах только синтетические canary secrets.

## Verification

Для Go-изменений запускай свежие focused tests, затем:

```bash
gofmt -d .
go vet ./...
go test ./...
```

Container acceptance test обязан доказать реальный runtime boundary. Если
Docker/Podman недоступен, такой тест может быть отмечен skipped, но walking
skeleton не считается подтверждённым.

Перед завершением сопоставь requirement links, actual diff, declared scope и
evidence. Critical и Important findings независимого reviewer должны быть
исправлены до закрытия Beads-задачи.
