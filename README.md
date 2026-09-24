# Antigravity Unlocker (Linux & Windows)

[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-blue.svg)](https://github.com/SatoKazuma1/Antigravity)
[![Rust](https://img.shields.io/badge/rust-1.80%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green.svg)](LICENSE)
[![GitHub release](https://img.shields.io/github/v/release/SatoKazuma1/Antigravity?include_prereleases)](https://github.com/SatoKazuma1/Antigravity/releases)

Кроссплатформенный инструмент для обхода региональных ограничений (*«User location is not supported»*, ошибка **400**) в **Google Antigravity** (2.0 / IDE / CLI), **Gemini API** и **Google AI Studio** без необходимости использовать сторонний VPN или менять регион аккаунта Google.

---

## 🚀 Особенности форка

* 🐧 **Полноценная поддержка Linux**:
  * Реализован DNS-слой: автоматический опрос DoH/DNS-провайдеров и пиннинг подменённых IP-адресов в `/etc/hosts`.
  * Автоматический сброс DNS-кэша (`resolvectl`, `systemd-resolve`, `nscd`).
  * Низкоуровневая привязка сокетов к исходящему интерфейсу провайдера (`SO_BINDTOIFINDEX`) — позволяет обходить ограничения без `CAP_NET_RAW`.
  * Фоновый пользовательский сервис через `systemd --user` без конфликтов с `systemd-resolved` (без необходимости захватывать 53 порт).
* 🤖 **Расширение доменов Google AI**:
  * В дополнение к CloudCode (`cloudcode-pa.googleapis.com`) перехватываются **Gemini API** (`generativelanguage.googleapis.com`) и **Google AI Studio** (`aistudio.google.com`).
* ⚡ **Устранение 30-минутного зависания при 400**:
  * В оригинальной версии при получении ошибки 400 единственный маршрут уходил в блокировку на 10–60 минут. Теперь пенальти ограничено 10 секундами с немедленной инвалидацией кэша и поиском свежего подменённого IP.
* 🔓 **Полное удаление лицензионных ключей**:
  * Больше нет никаких ограничений, задержек и необходимости получать ключи через Telegram-каналы.
* 🖥️ **Отзывчивый интерфейс без «чёрного ящика» (UI/UX Pro Max)**:
  * Живая телеметрия в реальном времени: отображение активного маршрута, задержки (ping ms), статуса каждого целевого домена.
  * Всегда видимый компактный терминал журналов (Live Telemetry).
* 📥 **Работа в системном трее**:
  * Сворачивание и закрытие в трей (на Linux и Windows) — при нажатии крестика программа не выгружается, а продолжает фоновое обслуживание запросов.

---

## 📦 Скачивание и установка

Скачайте последнюю версию со страницы [Releases](https://github.com/SatoKazuma1/Antigravity/releases).

### Linux

1. Скачайте архив `antigravity-unlocker-linux-x86_64.tar.gz` и распакуйте его:
   ```bash
   tar -xzf antigravity-unlocker-linux-x86_64.tar.gz
   cd antigravity-unlocker-linux-x86_64
   ```
2. Для добавления в меню приложений GNOME/KDE выполните:
   ```bash
   bash install.sh
   ```
   Или запустите напрямую без установки:
   ```bash
   bash launch.sh
   ```
   *(Программа запускается от обычного пользователя, sudo не требуется).*

### Windows

1. Скачайте `ag_unlocker.exe`.
2. Запустите файл (рекомендуется от имени администратора для настройки DNS-политик NRPT).
3. Нажмите **«Включить всё»**.

---

## 💻 Терминальный режим (TUI) одной командой

Для серверов по SSH или систем без графической оболочки:

**Linux**:
```bash
curl -fsSL https://raw.githubusercontent.com/SatoKazuma1/Antigravity/main/tui.sh | sh
```

**Windows (PowerShell)**:
```powershell
irm https://raw.githubusercontent.com/SatoKazuma1/Antigravity/main/tui.ps1 | iex
```

---

## 🛠️ Сборка из исходников

Для сборки требуется компилятор Rust (1.80+):

```bash
# Клонирование репозитория
git clone https://github.com/SatoKazuma1/Antigravity.git
cd Antigravity

# Сборка релизной версии
cargo build --release

# Упаковка готового дистрибутива под Linux
./package_release.sh
```

Готовый бинарник будет находиться в `target/release/ag_unlocker`, а релизный архив — в папке `dist/`.

---

## ⚙️ Как это работает

1. **Патч Language Server / CLI**:
   В бинарнике языкового сервера Antigravity безопасно переименовывается поле `ineligible` → `inexigible` и переменная прокси `https_proxy` → `AG_LS_PROXY`. Размер и структура исполняемого файла не меняются, поддерживается точный побайтовый откат.
2. **DNS-обход и ротация провайдеров**:
   Запросы к ключевым доменам Google AI направляются через пул свободных резолверов. Сервисы подменяют IP на адреса, не подпадающие под гео-блокировки Google.
3. **Локальный шлюз и Loopback Door**:
   Локальный сервис (`127.0.0.1:53129`) анализирует состояние маршрутов в реальном времени: если маршрут выдал ошибку 400, он мгновенно переключается на альтернативный рабочий туннель.

---

## 📄 Лицензия

Проект распространяется под лицензиями MIT и Apache 2.0. Оригинальный код © 2026 t.me/nova_txt. Модификации и поддержка Linux © 2026 SatoKazuma1.
