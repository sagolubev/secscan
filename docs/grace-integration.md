# GRACE в процессе разработки secscan

В исходном GRACE есть полезная автоматизация: CLI проверяет связи и контракты,
запускает объявленные проверки, собирает логи и показывает расхождения между
планом и репозиторием. Он может снять часть ручного учёта. Команды запускаются явно.
Установка skills сама по себе не включает фоновую проверку действий агента
или блокировку ошибок.

Для secscan я рекомендую применять GRACE через существующие OpenSpec, Beads и
`tracecheck`. Полный upstream CLI сейчас требует отдельной модели `.grace`;
готового адаптера OpenSpec/Beads в проверенных исходниках нет. При буквальном
внедрении пришлось бы поддерживать два набора требований, планов и статусов.

Проверено 6 сентября 2026 года: GRACE **4.1.0**, commit
[`fbb9009fc21f1b867f1823f7885d35e3fc7944f0`][upstream].
Исследованы canonical skills, CLI, выбранные regression tests и workflow CI.
Чужие installers, CLI и тесты локально не запускались. Состояние secscan для
сравнения — [`c406ed3`][secscan-base]. Это исследование; настройки и workflow
проекта не менялись.

Обновление 7 сентября: исправлен локальный verifier. Он учитывает HEAD, index
и рабочее дерево, связывает результат с точными байтами и путём manifest,
отклоняет baseline после изменения implementation и требует совпадения index
с рабочим деревом для target/final. Перед этими фазами выполните `git add`
для проверяемых файлов. Baseline задаётся полным commit SHA.
Sparse checkout и флаги index `assume-unchanged`/`skip-worktree` не поддерживаются:
verifier останавливается, поскольку Git может скрывать такие изменения.
По той же причине verifier отклоняет явные attributes `text`, `crlf`,
`eol`, `ident`, `filter` и `working-tree-encoding`, включая unset-формы.
Настройка `core.autocrlf`
не влияет на проверку: verifier сравнивает исходные байты.
Evidence v2 содержит время начала/окончания, статус каждой команды и digest
записи. Старый baseline перехода сохранён как legacy; новой цепочкой он не считается.
Новые фазовые результаты сохраняются комментариями в Beads. Команда
`--verify-evidence` проверяет сохранённую цепочку без повторного запуска сканеров.

## Что делает исходная тула

В CLI есть пять групп команд: `lint`, `status`, `module`, `verification`, `file`.
Команд наблюдения в фоне, управления агентами или автоматического исправления
артефактов в [entrypoint][entrypoint] нет. Изменение планов, исправление кода
и координацию работ skills поручают агенту.

| Задача | Что автоматизировано | Что остаётся за разработчиком и review |
| --- | --- | --- |
| Целостность модели | `lint` проверяет XML, маршруты графа, идентификаторы, ownership и форму контрактов. | Правильно ли описаны модули и их обещания. |
| Требование к состоянию | Assertions проверяют наличие/отсутствие файла или anchor, ownership, links, verification entry и текст в файле. | Соответствует ли поведение продуктовым требованиям. `MustVerify` означает наличие записи, а не успешный тест. |
| Запуск проверок | `MustPassCommand` с `--run-commands` запускает команды последовательно; есть остановка после ошибки, timeout, прогресс и логи. | Какие команды достаточны и проверяют ли assertions тестов нужное поведение. |
| Разные фазы изменения | `baseline` проверяет исходные условия; `target` — ожидаемый результат; `final` — target выбранного изменения и baselines остальных approved changes. | Получен ли baseline до правок и относится ли сохранённый результат к текущему коду. |
| Совместимость параллельных работ | `--parallel-preflight` превращает пересечения объявленных областей записи в ошибки. | Полнота scope, выдача задач и соблюдение владения файлами агентами. |
| Обзор состояния | `status` показывает здоровье модулей, active/archive changes и файлы, объяснённые scope. | Решение, как исправить расхождения; фактическое завершение или архивирование работы. |
| Поиск контекста | `module show --with verification`, `verification show` и `file show` связывают описание модуля, код и проверки. | Создание и поддержание содержательных связей. |

Механика реализована в [assertions][assertions], [выборе фаз][lint],
[проверке scope][scope] и [command runner][runner].
Например, обычный `current` не исполняет `MustPassCommand` без явного флага.
Для выбранных baseline/target/final объявленный command assertion без исполнения
выдаёт ошибку. После изменения поведения нельзя требовать старый baseline
выбранной работы: для этого и существует отдельная фаза `final`.

## Что нельзя принимать за гарантию

**`status` — отчёт, а не запрет записи.** По умолчанию `failOn=never`.
Даже режимы `errors`/`warnings` считают integrity errors и module health;
`unexplained-observed-drift` сам по себе не входит в расчёт exit code.
В [реализации status][status] расхождения вычисляются через `git status`,
включая неигнорируемые untracked files и оба пути rename. Сравнения полного
diff от baseline commit здесь нет. После commit чистое дерево перестаёт
показывать эти изменения. То же ограничивает обнаружение правок approved plans.

**Зелёное здоровье модуля не означает, что его тест прошёл.**
[Module health][health] проверяет наличие implementation files, commands,
scenarios и test files. Для markers он ищет признаки их эмиссии в исходниках.
Непустой `TraceAssertion` удовлетворяет требованию наличия evidence без запуска
соответствующего теста. Такой отчёт полезен для поиска пробелов в разметке,
но не заменяет runtime verification.

**Логи не образуют проверенную цепочку доказательств.**
[Run metadata][logs] содержит command, exit code, время, фазу и путь к логу,
но не commit, diff hash или хеш требований. Сохраняются последние десять запусков;
недоступность каталога логов допускает успешную проверку с предупреждением.
Команды исполняются через shell с полным stdout/stderr в логах, без обещания
маскирования секретов. Поэтому запуск команд из недоверенного plan.xml
небезопасен. Для secscan сохраняется свой runner с отдельными argv.

**Поддержка языков различается.** Для TS/JS есть compiler-backed анализ,
для Python и Dart нужны их runtimes. Для Go проверяется разметка, но не
соответствие `MODULE_MAP` реальным exports. Файлы без GRACE markers не становятся
governed автоматически. Это видно в [реестре языков][languages] и [lint][lint].
Поскольку secscan написан на Go, переход на полный XML-граф не даёт нам
автоматической проверки контрактов Go-кода.

Пакет требует Bun ≥ 1.3.14; Python/Dart добавляются при анализе соответствующих
языков ([package.json][package]). Upstream CI проверяет Linux, Windows и Dart,
но macOS job в [этом workflow][upstream-ci] нет. Завершение дочерних процессов
при timeout на macOS надо проверять отдельно: POSIX runner использует `setsid`
только при его наличии.

## Как это сочетается с нашим стеком

Текущий [AGENTS.md](../AGENTS.md) уже распределяет источники истины.
Наша адаптация GRACE проверяет связи между ними; новое место для редактирования
тех же требований не требуется.

| Часть процесса | Владелец в secscan | Роль GRACE-подхода |
| --- | --- | --- |
| Зачем меняем продукт, ожидаемое поведение, ограничения | OpenSpec proposal/specs/design | Требование должно вести к компоненту и наблюдаемой проверке. |
| Что выполнять сейчас, зависимости, статус и evidence | Beads через `br` | У outcome должны быть scope, ссылки на требования и результаты проверок. |
| Как реализовать и проверить поведение | Superpowers: brainstorming, TDD, debugging | Проверки выбираются до реализации; evidence сохраняет результат каждого нужного этапа. |
| Согласованность артефактов и изменённых файлов | `tracecheck`, staleness, OpenSpec validation | Механическая сверка ссылок, scope и проверенного состояния. |
| Смысл требований, качество тестов и безопасность | Независимый reviewer, профильные skills | Проверка, которую граф и exit code доказать не могут. |
| Готовность сборки и работа в целевой среде | Репозиторные тесты и CI | Повторяемое исполнение gates на конкретной ревизии. |

**Baseline не равен RED в TDD.** Baseline фиксирует исходное состояние и
сохраняемые свойства; он может быть зелёным. RED — ожидаемое падение нового
теста из-за отсутствующего поведения. GREEN — прохождение этого теста после
реализации; final включает нужную регрессию и review. Нельзя задним числом
назвать запуск после реализации baseline или заменить наблюдавшееся падение описанием
«этот тест должен был упасть». Сам GRACE CLI такой порядок не обеспечивает.

Наш [tracecheck](../cmd/tracecheck/main.go) связывает evidence с состоянием Git,
точным manifest и содержательными полями Beads. Он проверяет их до и после команд.
В upstream run metadata такой привязки нет. [Scope](../internal/tracecheck/git.go)
включает diff от baseline до HEAD, index и рабочего дерева, оба пути rename
и неигнорируемые untracked files.
В [CI](../.github/workflows/ci.yml) `--validate-only` проверяет ссылки, scope,
Go-разметку, authority и staleness; `--verify-evidence` проверяет сохранённую
цепочку относительно checkout. Отдельно проверяется экспорт/импорт Beads.
Source и container jobs выполняют свежие тесты. Validation JSON не объявляется
фазовым evidence.

CLI проверяет последовательность baseline → target → final и сохраняет полные
результаты в Beads. Target ссылается на baseline, final — на свежий target.
Записи включают статусы команд, объём и хеши вывода; для `go test -json` — число
passed/failed/skipped test events. Прогон без прошедших тестов не засчитывается.
Сырой stdout/stderr в репозиторий не попадает.

Ручными остаются содержательное связывание scenario с тестом, независимое review
и решение о закрытии outcome. Digest не доказывает авторство записи и честность
оператора. Verifier не может доказать достаточность assertions теста.
Измерения первоначального пилота приведены в [отдельной оценке](grace-pilot.md).

## Все skills и их место в процессе

В [canonical каталоге][skills] 15 skills. В таблице опущен общий префикс `grace-`.

| Группа | Skills | Как сочетаются с secscan |
| --- | --- | --- |
| Инициализация | `init`, `migrate` | Создают `.grace`. `migrate` переводит GRACE 3 в 4, а не OpenSpec в GRACE. |
| Требования и выполнение | `spec`, `plan`, `execute` | Пересекаются с OpenSpec, задачами `br` и выполнением по Superpowers. |
| Работа с кодом | `fix`, `refactor` | Дополняют debugging/TDD поиском по контрактам и обновлением связей при переносе, разделении и переименовании модулей. |
| Проверки | `verification`, `reviewer`, `refresh` | Дополняют tracecheck и review: связи module → tests, evidence и сверка расхождений. |
| Контекст | `ask`, `status`, `cli`, `explainer` | Помогают найти код, получить сводку и понять методику. Первые три ожидают `.grace`. |
| Делегирование | `setup-subagents` | Создаёт пресеты worker/reviewer. Запуск и координация остаются за native runtime. |

## Почему не стоит просто установить все skills

Upstream `grace-init` создаёт `.grace/context/requirements.xml` и меняет
проектный `AGENTS.md`. `grace-spec`/`grace-plan` создают собственные spec и plan,
включая `T-*` tasks, dependencies и acceptance criteria.
`grace-execute` управляет своими approved/applied/archive состояниями.
Это пересечение с OpenSpec и Beads подтверждается [шаблоном плана][plan-template]
и [skills][skills], а не только описанием в README.

Кроме того, `grace-execute` требует явного выбора sequential/parallel-safe,
отдельного подтверждения apply и решения resume/revert при частичных правках.
Буквальное копирование вернёт остановки, которые наш workflow сознательно
оставляет только для материальных решений. `grace-setup-subagents` добавляет
пресеты под `.grace`; сами агенты по-прежнему запускаются средствами runtime.

Можно адаптировать идеи `grace-verification`, `grace-refresh`, `grace-fix` и
`grace-reviewer`: поиск проверок от модуля, отчёт о drift, локализация ошибки,
review связей. Но их исходные версии тоже читают `.grace`.
Для secscan эти процедуры должны ссылаться на OpenSpec, `br` и `trace.json`.
Установка неизменённых файлов такого согласования не выполняет.

## Практический путь

Применять подход ко всем нетривиальным изменениям можно уже в нынешней модели.
OpenSpec описывает результат, `br` хранит задачи, TDD даёт проверяемое поведение.
`tracecheck` связывает результаты проверок с изменёнными файлами и состоянием
требований. Независимое review проверяет смысл этих связей.
Закрытие outcome следует за этими проверками. Мелкие безопасные правки
сохраняют короткий путь, заданный нашим workflow.

Перед правками задайте outcome, полный baseline SHA, scope и команды в
`trace.json`. Снимите baseline до изменения implementation, включая новые тесты.
Manifest должен оставаться тем же во всех трёх фазах. Изменение scope или набора
команд требует нового спланированного outcome.

```sh
go run ./cmd/tracecheck --phase baseline --run
# Реализация, TDD и независимое review.
git add <проверенные-файлы>
go run ./cmd/tracecheck --phase target --run
go run ./cmd/tracecheck --phase final --run
go run ./cmd/tracecheck --verify-evidence
br close <outcome> --reason "Проверки и review пройдены"
```

`--verify-evidence` сравнивает сохранённый final с текущим состоянием и проверяет
всю цепочку, включая команды и время фаз. Он не запускает тесты. Проверка нужна
перед закрытием задачи; сам `br close` не вызывает verifier. Комментарии попадают
в `.beads/issues.jsonl` через штатный `br sync --flush-only` и доступны после
импорта в новом checkout.

Старые записи перенесены с отдельным marker `secscan:tracecheck:legacy`, исходным
JSON и происхождением. У `.17` сохранена оговорка: baseline получен после правки
регрессионного теста. Такие записи не удовлетворяют новому gate. Записи v2
перехода `.27` также остаются legacy: для них ещё не было проверенной цепочки.

Если понадобится именно `grace lint`, возможны два других варианта: заменить
OpenSpec/Beads моделью `.grace` либо написать однонаправленную генерацию `.grace`
из существующих источников. Первый меняет принятый workflow; второй требует
собственного адаптера, правил обновления и проверки соответствия проекции.
Ни один не получается установкой skills. Для secscan дополнительная стоимость
пока не оправдана: главные пробелы находятся в обслуживании evidence,
а не в отсутствии ещё одного формата графа.

## Основания и граница исследования

Перед выбором решения выполнен локальный поиск GitHub-карточек по GRACE.
Карточка исходного репозитория описывает GRACE 3; соседний
`Baho73/grace-marketplace-2` — отдельный fork. Его AFK/Telegram-возможности
не приписываются `osovv/grace-marketplace`.

В исходниках regression tests проверяют выбор фаз и command opt-in
([lint tests][lint-tests]), dirty-path drift и rename
([status tests][status-tests]), fail-fast, timeout, логи и их отсутствие
([runner tests][runner-tests]). Для проверенного SHA GitHub сообщает успешный
[Validate run][validate-run]. Это подтверждает наличие реализованной и
тестируемой механики; локальную совместимость GRACE с secscan, полноценный
security audit и экономию времени этот разбор не устанавливает.

[upstream]: https://github.com/osovv/grace-marketplace/tree/fbb9009fc21f1b867f1823f7885d35e3fc7944f0
[secscan-base]: https://github.com/sagolubev/secscan/tree/c406ed3a1deaf18259c0053f75a7e8a5eaaa623e
[entrypoint]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace.ts
[assertions]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace4/assertions.ts
[lint]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/lint/core.ts
[scope]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace4/scope.ts
[runner]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace4/command-runner.ts
[status]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace-status.ts
[health]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/query/health.ts
[logs]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace4/run-log-store.ts
[languages]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/language-registry.ts
[package]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/package.json
[upstream-ci]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/.github/workflows/validate.yml
[plan-template]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/skills/grace/grace-plan/references/change-plan-template.xml
[skills]: https://github.com/osovv/grace-marketplace/tree/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/skills/grace
[lint-tests]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace-lint.test.ts
[status-tests]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace-status.test.ts
[runner-tests]: https://github.com/osovv/grace-marketplace/blob/fbb9009fc21f1b867f1823f7885d35e3fc7944f0/src/grace4/command-runner.test.ts
[validate-run]: https://github.com/osovv/grace-marketplace/actions/runs/33725145352
