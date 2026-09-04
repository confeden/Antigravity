# Antigravity Unlocker для macOS (Apple Silicon & Intel)

Полноценный порт утилиты разблокировки **Antigravity 2.0 / Antigravity IDE / CLI** для macOS (Darwin). Позволяет использовать агентские функции кодинга Google из любого региона (включая РФ и РБ) без необходимости включения стороннего VPN.

---

## ⚡️ Быстрый старт (Установка в 1 клик)

Откройте стандартный **Терминал (Terminal)** на Mac и выполните одну команду:

```bash
curl -fsSL https://raw.githubusercontent.com/Mysechka/AntigravityMacOsTest/main/macos/install.sh | bash
```

Скрипт полностью автоматически:
1. Проверит наличие инструментов сборки (Xcode Command Line Tools и Rust / Cargo).
2. Соберёт оптимизированный нативный бинарник под вашу архитектуру (**Apple Silicon M1–M4 / ARM64** или **Intel x86_64**).
3. Установит утилиту в `~/Library/Application Support/ag-unlocker`.
4. Создаст ярлык запуска в `~/Applications/Antigravity Unlocker.command` (можно запускать двойным кликом).
5. Снимет флаги карантина Gatekeeper и откроет меню утилиты.

---

## ⚙️ Как это устроено внутри macOS Bundle

### 1. Архитектура macOS .app бандла
В macOS приложение Antigravity представляет собой стандартный бандл:
```text
/Applications/Antigravity IDE.app/
└── Contents/
    ├── Info.plist
    ├── MacOS/
    │   └── Antigravity IDE                 <- Основной бинарник оболочки Electron
    ├── Resources/
    │   ├── app.asar (или app/)             <- Ресурсы IDE и расширений
    │   │   ├── out/main.js                 <- Точка входа Electron
    │   │   └── extensions/antigravity/bin/
    │   │       └── language_server_darwin_arm64  <- Сервер Language Server
    │   └── bin/
    │       └── language_server
```

### 2. Модификация бинарников и цифровая подпись (Code Signing)
* **Патч Language Server / CLI**: утилита находит `language_server` (включая платформенные суффиксы `_darwin_arm64`, `_darwin_x64`) и заменяет сигнатуру `ineligible` → `inexigible` без изменения длины строки.
* **Apple Silicon AMFI & Codesign**: на чипах Apple Silicon (ARM64) ядро macOS принудительно проверяет валидность цифровой подписи (Code Signature) каждого Mach-O бинарника. При изменении байт оригинальная подпись нарушается, и ядро убивает процесс сигналом `SIGKILL` (*«Antigravity server crashed unexpectedly»*).
  * **Решение**: анлокер автоматически вызывает `codesign --force --deep -s -` для каждого модифицированного бинарника и всего `.app` бандла, создавая валидную ad-hoc подпись, которую беспрепятственно принимает ядро macOS.

### 3. Локальный прокси и обход ошибки 400 (LaunchAgent)
В Windows обход региональной ошибки 400 («User location is not supported») опирается на службу NRPT DNS. В macOS системного аналога NRPT нет, поэтому реализован сетевой маршрут на базе **локального HTTP CONNECT прокси**:
1. Фоновый агент регистрируется в виде LaunchAgent:
   `~/Library/LaunchAgents/com.antigravity.proxy.plist`
   Он слушает локальный сокет `127.0.0.1:53129`.
2. Переменная окружения `HTTPS_PROXY` прописывается в графическую сессию Aqua через `launchctl asuser <uid> launchctl setenv HTTPS_PROXY http://127.0.0.1:53129`.
3. При обращении IDE к гейт-хостам Google (`cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com` и др.) локальный прокси запрашивает адреса через встроенные DoH/DNS unblocking-резолверы (`Comss`, `Malakhov`, `DNS_AI`) и направляет туннель через разрешённые европейские форвардеры. Внешний трафик не расшифровывается (end-to-end TLS), сторонние CA-сертификаты в систему не устанавливаются.

### 4. Системные разрешения macOS (TCC & Full Disk Access)
Начиная с macOS 13 (Ventura, Sonoma, Sequoia), подсистема безопасности **TCC (Transparency, Consent, and Control)** запрещает консольным программам модифицировать файлы внутри папки `/Applications`, даже если команда выполняется через `sudo` (от имени root).
* **Для успешного патча**: выдайте **Терминалу (Terminal / iTerm)** разрешение **«Полный доступ к диску» (Full Disk Access)**:
  * *Системные настройки → Конфиденциальность и безопасность → Полный доступ к диску → Включить Терминал*.

---

## 📋 Порядок первой разблокировки

1. **Полностью закройте Antigravity IDE** (`Cmd + Q`), если она была запущена.
2. Включите **«Полный доступ к диску»** для вашего Терминала.
3. Запустите скрипт установки:
   ```bash
   ./macos/install.sh
   ```
4. В появившемся меню нажмите **1** («Разблокировать / Пропатчить»).
   В блоке «ИТОГИ» должно отобразиться:
   ```text
   Успешно разблокированы:
     [+] Antigravity IDE
   ```
5. Запустите Antigravity IDE обычным способом и начните работу в Agent / Chat.

---

## 🛠 Управление и откат изменений

В главном меню анлокера доступны пункты:
* **`1`** — Разблокировать Antigravity (применить бинарный патч + прокси).
* **`2`** — Ввести собственный зарубежный HTTP-прокси (если есть свой VDS/сервер).
* **`3`** — Указать путь к установке Antigravity вручную (если приложение установлено в нестандартную папку).
* **`6`** — Отключить только фоновый прокси-маршрут.
* **`7`** — **Полный откат (Revert)**: восстанавливает оригинальные бинарники из `.ag_backup`, удаляет LaunchAgent и снимает переменные окружения `HTTPS_PROXY`.

---

## 🔍 Решение частых проблем

| Проблема | Причина | Решение |
|---|---|---|
| `[-] ... - Operation not permitted (os error 1)` | Защита TCC блокирует запись в `/Applications` | Откройте *Системные настройки → Конфиденциальность и безопасность → Полный доступ к диску* и включите Терминал. |
| `Antigravity server crashed unexpectedly` | Нарушена цифровая подпись на Apple Silicon | Выполните `sudo codesign --force --deep -s - "/Applications/Antigravity IDE.app"` или запустите пункт 1 в обновлённом анлокере. |
| `Agent execution terminated due to error` | Пиковая перегрузка серверов Google (503) или лимит запросов | Подождите 5–10 сек и нажмите кнопку повтора запроса, либо переключите модель на `Claude 3.7 Sonnet` или `Gemini Flash`. |
| Программа не видит Antigravity | Установлена в другую директорию | В меню анлокера выберите пункт **3** и укажите путь к файлу приложения. |
