[Türkçe](GELISTIRME.md) · [English](GELISTIRME_en.md) · **Русский**

# permwatch

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)

Аудитор разрешений и автозапуска для macOS на базе Endpoint Security. Пока это ядро для командной строки.

| `event` в выводе | Событие ES | Что фиксирует | macOS |
|---|---|---|---|
| `exec` | `NOTIFY_EXEC` | Запуск процесса. Бинарные файлы Apple отфильтрованы, но LOLBin и процессы с переменными окружения `DYLD_*` показываются всегда | 10.15+ |
| `btm_launch_item_add` | `NOTIFY_BTM_LAUNCH_ITEM_ADD` | Новый объект входа, LaunchAgent, LaunchDaemon | 13+ |
| `btm_launch_item_remove` | `NOTIFY_BTM_LAUNCH_ITEM_REMOVE` | Удаление объекта автозапуска (заметание следов) | 13+ |
| `quarantine_removed` | `NOTIFY_DELETEEXTATTR` | Удаление `com.apple.quarantine` (обход Gatekeeper) | 10.15+ |
| `gatekeeper_user_override` | `NOTIFY_GATEKEEPER_USER_OVERRIDE` | Пользователь нажал «Всё равно открыть» для заблокированного приложения | 15+ |
| `tcc_modify` | `NOTIFY_TCC_MODIFY` | Разрешение TCC выдано, отозвано или изменено (служба, приложение, причина) | 15.4+ |

Для каждого процесса записываются: `pid`, `ppid`, `responsible_pid`, путь, `signing_id`, `team_id`,
`signature` (`apple` / `developer` / `adhoc` / `unsigned`), исходные `cs_flags` и `cdhash`.
По cdhash можно искать в сервисах вроде VirusTotal.

Вывод в формате JSON Lines, одно событие на строку. Некорректные байты UTF-8 записываются как `�`,
поэтому `jq` не падает ни на одной строке.

### Почему не `eslogger`?

`eslogger`, входящий в macOS 13+, выводит те же события в виде сырого JSON. permwatch добавляет:
фильтр шума (системные бинарные файлы отбрасываются, но LOLBin остаются), события xattr, сведённые
только к удалению карантина, обнаружение инъекций через `DYLD_*`, упрощённую схему, а также
слои хранения, правил и интерфейса из дорожной карты. Для проверки сравните вывод с `eslogger`:

```sh
sudo eslogger btm_launch_item_add tcc_modify | jq .
```

## Приложение для macOS

Интерфейс на SwiftUI находится в `app/`. Xcode не нужен, достаточно Command Line Tools:

```sh
make app                          # app/build/permwatch.app
open app/build/permwatch.app
```

- Приложение **сканирует этот Mac**: читает все разрешения из пользовательской и системной
  баз TCC, объекты автозапуска из папок `LaunchAgents`/`LaunchDaemons` и проверяет подпись
  каждой программы. Повторное сканирование каждые 30 секунд выявляет отозванные разрешения
  и новые объекты (`~/Library/Application Support/permwatch/state.json`). Для этого нужен
  **полный доступ к диску**; если его нет, приложение об этом сообщит. Для ad-hoc сборок
  после каждой пересборки разрешение нужно выключить и включить снова.
- До получения entitlement для Endpoint Security нет перехвата в реальном времени и нет
  сведений о том, **какой процесс** внёс изменение; это задача ядра командной строки.
- **Файл → Открыть журнал событий…** открывает `events.jsonl` утилиты и следит за ним.
  **Загрузить демо-данные** показывает пример сценария.
- Интерфейс следует языку системы (13 языков). Переводы лежат в `app/i18n/<язык>.tsv`;
  при сборке проверяется, что в каждом языке есть все ключи и подстановки.
- Движок правил находится в `app/Sources/Analyzer.swift`.

## Сборка и тесты

```sh
make            # собирает и подписывает ad-hoc с entitlement
make test       # модульные тесты экранирования JSON (ES не нужен, работает на любом Mac)
```

## Почему не запускается на основном Mac?

`com.apple.developer.endpoint-security.client` — ограниченный entitlement. При включённом SIP
AMFI завершает ad-hoc подписанный бинарный файл с ним (exit 137 / SIGKILL). Есть два варианта:

1. **Для тестов:** виртуальная машина macOS с отключёнными SIP и AMFI (см. ниже).
2. **Для распространения:** запросить у Apple entitlement для ES, подписать Developer ID
   и пройти нотаризацию. (Заявка подана, на рассмотрении.)

## Тестовая ВМ (Apple Silicon, UTM)

1. Установите UTM и создайте ВМ через «Virtualize → macOS» (нужна macOS 15.4+, чтобы работал TCC_MODIFY).
2. Загрузите ВМ в режиме восстановления (в UTM: правый клик по ВМ → *Boot into Recovery Mode*).
3. В Терминале режима восстановления:
   ```sh
   csrutil disable
   ```
4. После обычной загрузки, внутри ВМ:
   ```sh
   sudo nvram boot-args="amfi_get_out_of_my_way=1"
   sudo reboot
   ```
5. Выдайте Терминалу **полный доступ к диску** (Системные настройки → Конфиденциальность и безопасность).
6. Скопируйте проект в ВМ, выполните `xcode-select --install`, затем `make && sudo ./permwatch`.

> ⚠️ Эти настройки серьёзно ослабляют защиту ВМ. Не делайте этого на основном компьютере.
> Запускайте образцы вредоносного ПО только в этой ВМ и только после снимка состояния.

## Вызов событий

```sh
# Терминал 1
sudo ./permwatch | tee events.jsonl | jq .

# Терминал 2 (без sudo)
./tests/trigger.sh
```

`trigger.sh` безопасно делает следующее: запускает LOLBin (`osascript`, `curl`), выполняет exec с
`DYLD_INSERT_LIBRARIES`, добавляет и удаляет флаг карантина, загружает и выгружает тестовый LaunchAgent.
Также он подсказывает, как вручную вызвать события TCC и Gatekeeper.

## Дорожная карта

- [x] Клиент ES: EXEC, BTM add/remove, TCC_MODIFY, удаление карантина, Gatekeeper override
- [x] Список разрешённых LOLBin, обнаружение `DYLD_*`, различение ad-hoc подписи, cdhash
- [x] Модульные тесты экранирования JSON, сборка в GitHub Actions
- [ ] Доступ к чувствительным файлам: `NOTIFY_OPEN` с инвертированным muting на отдельном `es_client`
      (LaunchAgents, TCC.db, Keychains, `~/.zshrc`, cookie браузеров)
- [ ] Инъекции: `NOTIFY_GET_TASK`, `NOTIFY_REMOTE_THREAD_CREATE`
- [ ] Привилегии и удалённый доступ: `NOTIFY_SUDO`, `NOTIFY_AUTHORIZATION_PETITION`,
      `NOTIFY_SCREENSHARING_ATTACH`, `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_XP_MALWARE_DETECTED`,
      `NOTIFY_PROFILE_ADD`
- [ ] Дерево процессов (`Safari → zsh → curl → osascript`)
- [ ] Файл правил в JSON (по образцу Sigma) и хранение в SQLite
- [ ] System Extension + XPC + интерфейс на SwiftUI
- [ ] Облегчённая версия: история микрофона через объекты процессов CoreAudio (App Store)
