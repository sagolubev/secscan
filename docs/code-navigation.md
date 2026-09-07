# Навигация по Go-коду через GRACE-комментарии

Комментарии дают агенту точку входа: назначение файла, важные ограничения,
символы и тесты. Требования остаются в OpenSpec, задачи и evidence — в Beads,
связи requirement → component → test — в `trace.json`. Каталог `.grace` не нужен.

Этот протокол адаптирует [исходную разметку GRACE][markup] на commit
[`fbb9009fc21f1b867f1823f7885d35e3fc7944f0`][upstream], проверенный 7 сентября 2026 года.

## Разметка файла

Перед изменением размеченного файла прочитай его контракт и связанные тесты.
Для каждого нового или изменённого Go-файла в `cmd/` и `internal/` добавь
короткий контракт и карту. Неизменённые legacy-файлы можно размечать по мере работы.
Размести их перед `package`, с пустой строкой после разметки.
Сохрани build constraints и обычные Go doc comments на своих местах.

Пример для [парсера Gitleaks](../internal/gitleaks/parser.go):

```go
// FILE: internal/gitleaks/parser.go
// START_MODULE_CONTRACT
// PURPOSE: Convert untrusted Gitleaks JSON into canonical findings.
// SCOPE: Reject paths outside the repository; omit Secret and Match fields.
// DEPENDS: internal/report/report.go
// LINKS: openspec/changes/build-secscan/specs/secscan/spec.md#requirement-canonical-finding-model, openspec/changes/build-secscan/trace.json, internal/gitleaks/parser_test.go#TestParseRedactsSecretMaterial
// ROLE: RUNTIME
// MAP_MODE: EXPORTS
// END_MODULE_CONTRACT
// START_MODULE_MAP
// Parse - Decode findings and enforce repository-relative paths.
// END_MODULE_MAP
```

В `DEPENDS` указывай важные локальные зависимости. Для их отсутствия используй `none`.
В `LINKS` используй пути от корня репозитория. `file.go#TestName` означает файл
и точное имя символа для поиска. Это локальное соглашение, не URL-якорь GitHub.
Ссылки на spec используют существующие заголовки. Статус задачи и результаты
проверок хранятся в Beads, а не в комментариях.

| Файл | `ROLE` | `MAP_MODE` | Содержимое карты |
| --- | --- | --- | --- |
| Рабочий модуль | `RUNTIME` | `EXPORTS` | Экспортируемые символы этого файла |
| CLI entrypoint | `SCRIPT` | `LOCALS` | Точки входа и важные локальные функции |
| Существенный тестовый файл | `TEST` | `LOCALS` | Тесты и важные test helpers |

Эти пары совпадают с [правилами upstream][parser]. Для `*_test.go` указывай `ROLE`
явно: upstream не распознаёт этот Go-суффикс в `inferRole`.
Карта содержит имена символов, а не номера строк. При переименовании символа
обнови карту и ссылки на него в том же изменении.

## Контракты функций и границы внутри кода

Добавляй отдельный контракт функции там, где типы не выражают существенное
ограничение входа, результата или побочного эффекта. Сохраняй обычный Go doc
comment непосредственно перед объявлением. Пример:

```go
// START_CONTRACT: Parse
// PURPOSE: Decode scanner output at the trust boundary.
// INPUTS: data: []byte - Untrusted Gitleaks JSON.
// OUTPUTS: []report.Finding or error; Secret and Match fields are absent.
// SIDE_EFFECTS: none
// LINKS: internal/gitleaks/parser_test.go#TestParseRedactsSecretMaterial, internal/gitleaks/parser_test.go#TestParseRejectsPathOutsideRepository
// END_CONTRACT: Parse

// Parse converts Gitleaks JSON into canonical findings.
```

Для важного участка внутри длинной функции используй парные маркеры:
`// START_BLOCK_VALIDATE_REPOSITORY_PATH` и `// END_BLOCK_VALIDATE_REPOSITORY_PATH`.
Имя описывает назначение участка и уникально внутри файла.
Токен маркера занимает отдельную строку комментария. Имена и регистр пары совпадают.
Закрывай вложенные блоки в обратном порядке. Эти требования следуют
[исходной грамматике][parser]. Короткой функции достаточно контракта.

В canonical разметке нет отдельных полей `INVARIANT` и `TESTS`.
Фиксируй существенный инвариант в `SCOPE`, `INPUTS`, `OUTPUTS` или `SIDE_EFFECTS`.
Связывай его с конкретным тестом через `LINKS`.

## Поиск и проверка

Из корня репозитория:

```sh
rg -n 'START_MODULE_CONTRACT|START_MODULE_MAP|START_CONTRACT:|START_BLOCK_' cmd internal
rg -n 'func TestParseRedactsSecretMaterial' internal/gitleaks/parser_test.go
go test ./internal/gitleaks -run '^TestParseRedactsSecretMaterial$' -count=1
```

`go run ./cmd/tracecheck --validate-only` проверяет разметку по Go AST:
парность маркеров, ROLE/MAP_MODE, символы карты, exports и локальные ссылки.
Строки с примерами маркеров внутри Go literals разметкой не считаются.
Проверяются все размеченные файлы и наличие разметки у новых/изменённых файлов.
Для метода указывай `Type.Method`, например `Evidence.Seal`.

Перед завершением сверь инварианты с assertions тестов. Выполни target/final
из связанного outcome и `--verify-evidence`. Сам комментарий не доказывает
прохождение теста; достаточность проверки остаётся предметом review.

Это адаптация навигации по исходникам. Она сохраняет canonical маркеры, но заменяет
`M-*`/`V-M-*` и XML-граф upstream существующими путями OpenSpec, кода и тестов.
Версии файлов и `CHANGE_SUMMARY` остаются в Git. Контракты каждой экспортируемой
функции и trace-логи блоков из полного GRACE здесь не обязательны.

Upstream [распознаёт Go-файлы][languages], но не имеет Go adapter для проверки
соответствия `MODULE_MAP` экспортам. Локальный `tracecheck` проверяет эту связь
через Go AST вместе с manifest и evidence. Смысл контрактов и полноту тестов
проверяет review. Разбор всего workflow —
в [grace-integration.md](grace-integration.md).

[upstream]: https://github.com/osovv/grace-marketplace/tree/fbb9009fc21f1b867f1823f7885d35e3fc7944f0
[markup]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/skills/grace/grace-explainer/references/semantic-markup.md
[parser]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/project-utils.ts
[languages]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/language-registry.ts
