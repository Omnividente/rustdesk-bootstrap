# rustdesk_bootstrap

RU: Локальный bootstrap-установщик RustDesk под Windows 7+. Делал для себя и своего удобства, может кому-то еще пригодится.

EN: Local RustDesk bootstrap installer for Windows 7+. Built for my own use and convenience, maybe it will be useful for others too.

---

# RU

## На каких системах работает
- Windows 7 и новее (x86/x64).
- Ориентировано на “чистые” системы без установки дополнительного софта.
- Тестировалось на Win7/Win10/Win11 в доменной среде.

## Быстрый старт
1) Создайте локальный конфиг:
   - скопируйте `config.example.rs` в `config.local.rs`
   - заполните реальные значения

2) Сборка:
```
cargo build --release
```

3) Запуск:
```
rustdesk_bootstrap.exe --silent
```

## Параметры запуска
- `--local-installer=PATH`  Локальный MSI/EXE RustDesk (рекомендую для оффлайн)
- `--force-x86`             Принудительно x86-установщик
- `--silent` / `--quiet`    Без паузы в конце

## Настройки (config.local.rs)
Обязательные:
- `HBBS` — адрес ID-сервера в формате `HOST:PORT`
- `KEY`  — публичный ключ вашего RustDesk сервера

Необязательные:
- `RELAY` — адрес relay-сервера `HOST:PORT` (если нужен)
- `PERM_PASSWORD` — постоянный пароль (если нужен)

Пример (`config.example.rs`):
```
pub const HBBS: &str = "example.com:21116";
pub const KEY: &str = "PASTE_PUBLIC_KEY_HERE";
pub const RELAY: Option<&str> = None; // Some("relay.example.com:21117")
pub const PERM_PASSWORD: Option<&str> = None; // Some("YourPasswordHere")
```

## Безопасность
- Не коммитьте реальные ключи/пароли в git.
- `config.local.rs` добавлен в `.gitignore`.

---

# EN

## Supported systems
- Windows 7 and newer (x86/x64).
- Designed for “clean” systems without extra software.
- Tested on Win7/Win10/Win11 in a domain environment.

## Quick start
1) Create local config:
   - copy `config.example.rs` to `config.local.rs`
   - fill in real values

2) Build:
```
cargo build --release
```

3) Run:
```
rustdesk_bootstrap.exe --silent
```

## CLI flags
- `--local-installer=PATH`  Use local RustDesk MSI/EXE (recommended for offline)
- `--force-x86`             Force 32-bit installer
- `--silent` / `--quiet`    No pause at the end

## Settings (config.local.rs)
Required:
- `HBBS` — ID server in `HOST:PORT` format
- `KEY`  — public key for your RustDesk server

Optional:
- `RELAY` — relay server `HOST:PORT` (if needed)
- `PERM_PASSWORD` — permanent password (if needed)

Example (`config.example.rs`):
```
pub const HBBS: &str = "example.com:21116";
pub const KEY: &str = "PASTE_PUBLIC_KEY_HERE";
pub const RELAY: Option<&str> = None; // Some("relay.example.com:21117")
pub const PERM_PASSWORD: Option<&str> = None; // Some("YourPasswordHere")
```

## Security
- Do NOT commit real keys/passwords to git.
- `config.local.rs` is ignored via `.gitignore`.
