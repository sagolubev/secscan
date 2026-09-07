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

Первый implementation outcome — walking skeleton с Gitleaks. Остальные scanner
adapters остаются заблокированы до прохождения его acceptance, security review
и независимого review.

## GRACE Pilot

OpenSpec и Beads остаются авторитетными; `.grace` не создаётся.

Тонкий verifier должен проверять:

- связи `requirement -> component -> test`;
- раздельные `baseline`, `target` и `final` evidence;
- свежесть evidence относительно проверенного Git-состояния;
- соответствие полного changed-file set заявленному scope.

Trace metadata содержит только ссылки и команды. Не копируй в него текст
требований, дизайн или задачи.

При изменении ключевого Go-модуля читай и поддерживай его GRACE contract/map.
Формат и условия применения: [docs/code-navigation.md](docs/code-navigation.md).
Ссылки ведут в OpenSpec и tests; task status и evidence остаются в Beads.

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
