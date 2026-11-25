# Сборка проекта

## Готовый релиз

Для запуска распакованного `ProxyServer.exe` из корня не требуется компилятор или установленный Go. Рядом должны находиться:

- `components\gost.exe`;
- `components\mtg.exe`;
- `components\proxy-cert.exe`.

Целевая система релиза — **Windows 10 Pro x64**. Готовый GUI собран MSVC v143 на Windows Server 2022 со статическим C++ runtime (`/MT`); в архив включён именно EXE успешного Windows CI. Сетевые компоненты — прежние рабочие статические Go-приложения без CGO из версии 2.0. Код UI нативный Win32, без .NET/WPF/Electron.

## Visual Studio: оболочка

1. Установите Visual Studio с workload «Разработка классических приложений на C++» и Windows SDK.
2. Откройте **ProxyServer.sln**.
3. Выберите **Release / x64**.
4. Выполните «Сборка → Собрать решение».
5. Запустите `bin\x64\Release\ProxyServer.exe`. MSBuild копирует комплектные компоненты в `bin\x64\Release\components`.

`Build.cmd` ищет установленный MSBuild и выполняет ту же сборку. В `.sln` также сохранена Win32-конфигурация оболочки для совместимости проекта; поставляемые компоненты x64 всё равно требуют 64-разрядную Windows. Для релиза используйте x64.

Проект задаёт C++11-совместимые исходники, статический CRT в MSVC, Unicode, ASLR/DEP и requireAdministrator manifest. Для VS2015/2017/2019 предусмотрен выбор v140/v141/v142; для новых VS используется установленный toolset. При необходимости выберите доступную версию Windows 10 SDK. Дополнительно выполнена строгая кросс-сборка MinGW. MSBuild v143 и исполнение службы проверены в Windows CI; конкретный запуск и границы проверки указаны в VERIFICATION.md. Наличие конфигурации v140 не является заявлением о выполненном запуске компилятора VS2015.

Производственные единицы компиляции:

- `main_win.cpp`: интерфейс, DPAPI, INI, журнал, автозапуск;
- `gost_config.cpp`: проверка настроек и JSON в stdin;
- `proxy_backend_win.cpp`: управление GOST и закрытые локальные метрики;
- `child_process_win.cpp`: контролируемый запуск дочерних процессов;
- `mtproto_win.cpp`: генерация секрета и управление mtg;
- `service_host_win.cpp`: SCM, защищённая установка, профиль, локальный IPC и восстановление процессов;
- `service_codec.cpp`: ограниченный версионированный формат профиля и сообщений;
- `service_firewall_plan.cpp`: расчёт разрешённых программ, портов и IP;
- `service_firewall_win.cpp`: управление только собственными правилами через Windows COM API.

Готовые Go-ядра не собираются как C++-проекты и не требуют NuGet. Полный исходный код поставленных версий расположен в `third_party`.

## Пересобрать сетевые компоненты

Нужен **Go 1.26.11** или совместимая более новая версия. Выполните `Rebuild-Components.cmd` из корня. Скрипт использует CGO=0, GOAMD64=v1, GOOS=windows, GOARCH=amd64, GOTOOLCHAIN=local и останавливается при ошибке. Он не устанавливает компилятор сам. При первом запуске Go загружает версии библиотек по `go.mod`/`go.sum`.

| Компонент | Исходники | Отличие от upstream |
|---|---|---|
| GOST 3.3.3-desktop.1 | `third_party\gost`, `third_party\gost-x` | Проверка DNS TLS/порт DoT и HTTP hop headers |
| mtg 2.3.0-desktop.1 | `third_party\mtg` | stdin до 64 KiB и отключение необязательной стартовой диагностики |
| proxy-cert | `tools\certgen` | Локальный генератор серверного сертификата |

Описания и diff находятся в соответствующих папках `DESKTOP_INTEGRATION.md` / `DESKTOP_PATCH.diff`. Не заменяйте EXE upstream-версией молча: mtg без нашей stdin-правки не принимает используемую оболочкой команду, а GOST без описанных исправлений отличается поведением.

Версии, исходные commits, SHA-256 и Go build info — `docs\third_party\Components-provenance.json` и соседние JSON. Бинарная воспроизводимость может зависеть от версии Go/SDK/компилятора; контрольные суммы поставленного релиза записаны отдельно.

## CMake

Для Windows доступен альтернативный `CMakeLists.txt`. Он собирает те же девять единиц и копирует `components`. На Linux можно собрать переносимую утилиту проверки конфигурации и тесты кодека/плана брандмауэра:

```sh
cmake -S . -B build -DPROXY_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
python3 tests/test_gost.py --gost /path/to/linux/gost --config-cli build/proxy_config_test
```

Для сетевых тестов нужен Linux GOST из той же изменённой версии, Python 3 и `openssl` для временного тестового сертификата. Тесты работают на loopback и не читают рабочий `proxy.ini`. Реальные секреты не нужны. `tests/config_cli.cpp` выводит только тестовую конфигурацию и не используется GUI.

Отдельные проверки Go:

```text
third_party/gost-x: go test ./handler/http ./resolver/exchanger
tools/certgen:      go test ./...
third_party/mtg:    go test ./internal/config ./internal/utils ./mtglib/...
```

Подробные фактические результаты и ограничения проверки — `VERIFICATION.md`.

## Репозиторий исходников

В GitHub не включаются пользовательские INI, ключи, журналы или собранные EXE. После клонирования выполните `Rebuild-Components.cmd`, затем соберите решение. Полный готовый ZIP уже содержит все компоненты.

Тест `tests/Run-ServiceTests.ps1` предназначен для отдельного одноразового GitHub-hosted Windows runner. Для приёмки на своей VDS используйте обычную установку через GUI и шаги из `docs/SERVICE.md`.
