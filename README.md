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
1) Создайте конфиг:
   - `rustdesk-bootstrap.toml` рядом с EXE, или
   - `C:\ProgramData\RustDeskDeploy\config.toml`

Шаблон — `config.example.toml`.

2) Запуск:
```
rustdesk_bootstrap.exe --silent
```

## Параметры запуска
- `--local-installer=PATH`  Локальный MSI/EXE RustDesk (рекомендую для оффлайн)
- `--force-x86`             Принудительно x86-установщик
- `--silent` / `--quiet`    Без паузы в конце
- `--config=PATH`           Явный путь к конфигу

## Настройки (config.toml)
Обязательные поля:
- `hbbs` — адрес ID-сервера в формате `HOST:PORT`
- `key`  — публичный ключ вашего RustDesk сервера

Необязательные:
- `relay` — адрес relay-сервера `HOST:PORT` (если нужен)
- `perm_password` — постоянный пароль (если нужен)

Пример:
```
hbbs = "example.com:21116"
key = "PASTE_PUBLIC_KEY_HERE"
# relay = "relay.example.com:21117"
# perm_password = "YourPasswordHere"
```

## Безопасность
- Не коммитьте реальные ключи/пароли в git.
- Храните конфиг вне репозитория.

## Сборка
Пример для Windows (mingw):
```
cargo build --release
```

Сборка под Win7+ выполняется профилем `release`. Готовый EXE:
`target\release\rustdesk_bootstrap.exe`

---

# EN

## Supported systems
- Windows 7 and newer (x86/x64).
- Designed for “clean” systems without extra software.
- Tested on Win7/Win10/Win11 in a domain environment.

## Quick start
1) Create config:
   - `rustdesk-bootstrap.toml` next to the EXE, or
   - `C:\ProgramData\RustDeskDeploy\config.toml`

Template: `config.example.toml`.

2) Run:
```
rustdesk_bootstrap.exe --silent
```

## CLI flags
- `--local-installer=PATH`  Use local RustDesk MSI/EXE (recommended for offline)
- `--force-x86`             Force 32-bit installer
- `--silent` / `--quiet`    No pause at the end
- `--config=PATH`           Explicit config file path

## Settings (config.toml)
Required:
- `hbbs` — ID server in `HOST:PORT` format
- `key`  — public key for your RustDesk server

Optional:
- `relay` — relay server `HOST:PORT` (if needed)
- `perm_password` — permanent password (if needed)

Example:
```
hbbs = "example.com:21116"
key = "PASTE_PUBLIC_KEY_HERE"
# relay = "relay.example.com:21117"
# perm_password = "YourPasswordHere"
```

## Security
- Do NOT commit real keys/passwords to git.
- Keep your config outside the repository.

## Build
Example for Windows (mingw):
```
cargo build --release
```

Build for Win7+ uses the `release` profile. Output:
`target\release\rustdesk_bootstrap.exe`
