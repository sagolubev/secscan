# Оценка пилота GRACE в secscan

**Статус на 7 сентября:** это историческая оценка commit `e188874`.
В текущем verifier исправлен учёт index, добавлена привязка к точному manifest,
переносимая цепочка evidence в Beads, проверка Go-разметки и CI gates.
Старые записи сохранены как legacy, без исправления дат или результатов.
Текущий порядок работы описан в [grace-integration.md](grace-integration.md).

**Вывод:** тонкий verifier полезен как проверка полноты ссылок и границ изменения.
Его стоит сохранить. Доказательств, что GRACE ускорил разработку или уменьшил число дефектов, этот пилот не даёт.
Основная доказанная польза — явные отложенные требования и воспроизводимая запись выполненных проверок.
Гарантии свежести evidence пока слабее, чем можно заключить из наличия SHA-256.

Оценка от 6 сентября 2026 года фиксирует состояние [e188874c2a3b69dec29cc49d108743ec27949694][base].
Последующие изменения публикации и CI сюда не включены.
«GRACE» здесь означает локальные `cmd/tracecheck`, `internal/tracecheck` и `trace.json`.
Полная модель GRACE, отдельная `.grace` и второй tracker не внедрялись.

## Что действительно проверяется

| Механизм | Наблюдаемая гарантия | Граница гарантии |
| --- | --- | --- |
| Ссылки scenario → component → test | Каждая пара requirement/scenario перечислена ровно один раз: `target` или `deferred`. Для target/final указанные пути существуют. | Проверяется `os.Stat`, а не смысл кода, имя теста, запуск теста или качество assertions. |
| Отложенный сценарий | Требуется непустое поле `issue`. | Существование этой задачи и её статус verifier не проверяет. |
| Scope | Git diff от baseline и неигнорируемые untracked paths сверяются с разрешёнными файлами/каталогами. Для rename проверяются оба пути. | Это итоговое состояние рабочего дерева, не независимый снимок index. Игнорируемые untracked files не учитываются. Широкий разрешённый каталог допускает любые изменения внутри него. |
| Фазы | `--phase baseline/target/final --run` выполняет объявленные argv последовательно и останавливается при ошибке. JSON содержит результаты, duration, cwd и хеши. | Выбор фазы не доказывает, что предыдущие фазы выполнены. Пустой список checks даёт успех. |
| Identity | Хеш связывает baseline, статусы/пути изменений, содержимое и режим файлов. Evidence sink исключён. | Хеш вычисляется до checks. Повторного сравнения после checks и автоматической проверки старого evidence нет. |
| Beads authority | `br show --json` проверяет parent выбранного outcome против `.br-link`; содержательные поля и отсортированные dependencies входят в отдельный хеш. | Notes, timestamps и status исключены намеренно. Хеш не доказывает выполнение acceptance criteria или независимого review. |

Реализация этих правил находится в [tracecheck.go][trace], [git.go][git] и [evidence.go][evidence].
Сборка фазового результата находится в [cmd/tracecheck/main.go][main].
Scope проверяется относительно редактируемого manifest: расширение scope требует содержательного review, даже если verifier после этого зелёный.

## Что показал пилот

| Измерение | Результат | Как получено |
| --- | --- | --- |
| Начальная карта | 40 сценариев: 13 target, 27 deferred | `trace.json` в [7f332cb][initial] |
| Карта на момент оценки | 70 сценариев: 50 target, 20 deferred | `trace.json` в `e188874` |
| Код verifier | 603 строки Go без тестов | `cmd/tracecheck/main.go` и три файла `internal/tracecheck` |
| Тесты verifier | 287 строк, 12 тестов и один subprocess helper | `internal/tracecheck/tracecheck_test.go` |
| Trace metadata | 897 строк, 22 161 байт UTF-8 | `trace.json`, без текста требований |
| Сохранённые evidence | 35 JSON-документов: 7 baseline, 14 target, 14 final | `notes` задач `secscan-ij8.1`–`secscan-ij8.10` через `br show --json` |
| Объём notes этих задач | 78 319 байт UTF-8 | Включает evidence, review и пояснения, не только накладные расходы GRACE |
| Время сохранённых final checks | 2,023–118,199 секунды на запуск | Сумма `checks[].durationMs` каждого final JSON |

Количество target выросло одновременно с расширением спецификации.
Это учёт заявленного покрытия, не процент проверенной функциональности.
Среди 20 deferred остаются rootless acceptance, suppressions, baselines, scoped scans, HTML/SARIF и LLM analysis.
Закрытые scanner outcomes не означают выполнения всего proposal.

Сохранённые JSON не являются полным журналом попыток: количество baseline-записей не доказывает количество реально выполненных baseline-проверок.
Время checks также не измеряет работу агента, review, загрузки assets или накладные расходы самого verifier.
В последнем final для `secscan-ij8.10` сумма составляет 117,449 секунды; container acceptance занимает 116,023 секунды.
Тестирование реальных scanners было бы нужно и без GRACE.

## Польза и цена на конкретных примерах

Проверка scope и точного списка сценариев делает забытый файл или потерянную ссылку обнаружимой механической ошибкой.
Тесты демонстрируют отказ при пропущенном сценарии и rename из запрещённого каталога.
История [6194b6e][bind] и [86c2a91][harden] показывает, что сам verifier потребовал доработок: привязки authority, учёта file mode и проверки пустого вывода `gofmt`.
Это небольшой отдельный инструмент, но уже не бесплатная декларация в инструкции.

В `secscan-ij8.5` и `.6` сохранены повторные target/final, которые явно заменяют evidence до staging.
Причина чувствительности видна в коде: статус `??` после добавления файла в index становится `A` и меняет identity при тех же байтах.
В `.7` committed-state сверяли реальным повтором target, поскольку отдельного режима проверки identity не было.
Сумма checks этого повтора — 51,048 секунды.
Запись evidence в Beads не меняет identity благодаря исключению sink, но обычные изменения manifest требуют нового запуска.

Независимые reviewers нашли другие классы ошибок: UID ownership (`.5`), учёт отдельных dependency inputs (`.8`), потерю частичного OCI evidence (`.10`).
Эти исправления нельзя записывать в результат GRACE.
Их источник — review, тесты и реальные runtime-пробы.
OpenSpec дал требования, Beads — исполняемые outcomes и зависимости, TDD — проверяемое поведение, review — независимую оценку смысла изменений.
Verifier добавил механическую сверку этих артефактов.

## Ограничения, которые важно сохранить в выводе

Identity до запуска не доказывает неизменность дерева во время checks: другой процесс или сам check может изменить файлы.
Старый JSON verifier не загружает и не сравнивает с текущим состоянием.
Baseline, target и final не образуют автоматически проверенную цепочку; `ok: true` относится только к выбранному запуску.
Выходные логи и причины skipped tests в evidence не сохраняются: exit code 0 сам по себе не доказывает runtime readiness.
Локальные `openspec`, `opsx-stale` и `br` также должны быть доступны; на оценённом commit обязательного GitHub CI gate ещё нет.

При подготовке оценки пакет verifier из `e188874` прошёл свежий `go test -count=1 -v .` в отдельном временном каталоге.
Дополнительные временные пробы подтвердили принятие постороннего существующего файла как test path, успех пустой фазы и зависимость identity от `??`/`A`.
Пробные файлы не добавлены в проект. Эти результаты подтверждают границы реализации, а не закрывают их.

## Что оставить и что улучшить

Сохранить один manifest и существующий `br`; расширять пилот до отдельного workflow framework оснований нет.
Ближайшее полезное улучшение — обязательный переносимый CI gate для ссылок, scope и staleness с явным отличием validation от выполненных checks.
Для надёжной свежести нужны сравнение identity/authority до и после checks, запрет пустых фаз и проверка сохранённого evidence без повторного запуска scanners.
Смысл requirement → test по-прежнему оставлять review и acceptance tests: дополнительный граф сам по себе это не докажет.
Обещания экономии времени или tokens требуют сравнимого процесса без verifier и измерений; таких данных в пилоте нет.

## Что изменено при подготовке открытой публикации

После зафиксированного baseline добавлены `--validate-only`, строгая проверка
`.stale.json`, запрет пустых phase checks и повторная сверка scope/state/authority
после выполнения checks. Это подтверждено новыми regression tests в
[`cmd/tracecheck/main_test.go`](../cmd/tracecheck/main_test.go) и
[`internal/tracecheck/staleness_test.go`](../internal/tracecheck/staleness_test.go).
Validation остаётся отдельным режимом и не притворяется выполненным evidence.

[GitHub CI](../.github/workflows/ci.yml) связывает эту проверку с source tests и
сборками; фактическое hosted readiness определяется результатом workflow run.
Смысл связей requirement → test, корректность выбранного scope и доверие к
содержимому checks по-прежнему требуют review. Автоматического доказательства
экономии времени или полного semantic coverage эти изменения не добавляют.

[base]: https://github.com/sagolubev/secscan/tree/e188874c2a3b69dec29cc49d108743ec27949694
[initial]: https://github.com/sagolubev/secscan/blob/7f332cba4399175e23e2433ce285190bf73d3d6a/openspec/changes/build-secscan/trace.json
[trace]: https://github.com/sagolubev/secscan/blob/e188874c2a3b69dec29cc49d108743ec27949694/internal/tracecheck/tracecheck.go
[git]: https://github.com/sagolubev/secscan/blob/e188874c2a3b69dec29cc49d108743ec27949694/internal/tracecheck/git.go
[evidence]: https://github.com/sagolubev/secscan/blob/e188874c2a3b69dec29cc49d108743ec27949694/internal/tracecheck/evidence.go
[main]: https://github.com/sagolubev/secscan/blob/e188874c2a3b69dec29cc49d108743ec27949694/cmd/tracecheck/main.go
[bind]: https://github.com/sagolubev/secscan/commit/6194b6e53ad1ea6c370df6e17fb3a62605cc77a4
[harden]: https://github.com/sagolubev/secscan/commit/86c2a91773a205e2830ca4785fea6b2543921be0
