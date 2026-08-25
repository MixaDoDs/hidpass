# hidpass

Безопасная Linux CLI-утилита для обнаружения настраиваемых USB/HID-устройств
и выдачи доступа к их узлам `/dev/hidraw*` без ручного поиска VID/PID и
написания udev-правил.

`hidpass` подходит для клавиатур, мышей, Stream Deck и других устройств,
которые настраиваются через WebHID или фирменный конфигуратор.

Правила создаются точечно, через `TAG+="uaccess"`. Утилита не использует
глобальный `MODE="0666"` и не открывает доступ ко всем HID-устройствам.

## Возможности

- обнаружение устройств через `/dev/hidraw*` и `udevadm` без root-доступа;
- fallback через sysfs, если udev не сообщает VID/PID;
- дедупликация нескольких HID-интерфейсов одного физического устройства;
- классификация: `keyboard`, `mouse`, `streamdeck`, `touchpad`, `tablet`,
  `joystick`, `other-hid`;
- интерактивный режим `auto` и автоматический режим `auto --yes`;
- автоматическое исключение YubiKey/FIDO, Ledger, Trezor, Nitrokey и других
  чувствительных security-устройств;
- точечный файл правил `/etc/udev/rules.d/70-hidpass.rules`;
- отдельное состояние в `/etc/hidpass/devices.json`;
- повышение прав только для операций записи через `pkexec` или `sudo`;
- подробная диагностика через `scan --debug` и `doctor`;
- модульная архитектура и unit/regression tests без внешних Go-зависимостей.

## Быстрый старт

### Сборка из исходников

Требуется Go 1.18 или новее.

```bash
git clone https://github.com/MixaDoDs/hidpass.git
cd hidpass
go test ./...
go build -trimpath -o hidpass ./cmd/hidpass
```

Для систем, где Go пытается добавить VCS-метаданные вне Git-репозитория:

```bash
GOFLAGS=-buildvcs=false go test ./...
```

### Установка

```bash
sudo install -o root -g root -m 0755 hidpass /usr/local/bin/hidpass
```

После установки запускайте утилиту от обычного пользователя:

```bash
hidpass scan
hidpass auto
```

При необходимости `hidpass` сам покажет стандартное окно Polkit через
`pkexec`. Если `pkexec` отсутствует, используется `sudo`.

## Команды

| Команда | Назначение |
| --- | --- |
| `hidpass scan` | Найти и классифицировать подключённые HID-устройства |
| `hidpass scan --debug` | Показать udev/sysfs-диагностику для каждого hidraw-узла |
| `hidpass list` | Показать настроенные VID:PID |
| `hidpass auto` | Предложить устройства по одному и запросить подтверждение |
| `hidpass auto --yes` | Добавить все подходящие устройства без вопросов |
| `hidpass allow 373e:001e` | Явно разрешить конкретный VID:PID |
| `hidpass remove 373e:001e` | Удалить VID:PID из конфигурации |
| `hidpass apply` | Пересобрать rules-файл и перезагрузить udev |
| `hidpass doctor` | Проверить окружение, права, udev и конфигурацию |
| `hidpass version` | Показать версию сборки |

Пример обычного сценария:

```text
$ hidpass scan
373e:001e  mouse       LAMZU MAYA X 8K Receiver
19f5:fee0  keyboard    NuPhy Air60 HE

$ hidpass auto
Allow 373e:001e [mouse] LAMZU MAYA X 8K Receiver? [Y/n]
```

## Как это работает

Утилита начинает поиск с `/dev/hidraw*`, затем выполняет для каждого узла:

```bash
udevadm info --query=property --name=/dev/hidrawN
```

Если udev не сообщает VID/PID, `hidpass` разрешает
`/sys/class/hidraw/hidrawN/device` и поднимается вверх по sysfs до родителя с
`idVendor` и `idProduct`.

Проект намеренно не обходит `/sys/bus/usb/devices`: этот каталог содержит
много symlink-ов, а `filepath.WalkDir` в Go не заходит внутрь symlink-директорий.

Несколько HID-интерфейсов одной физической мыши или клавиатуры объединяются по
VID/PID и родительскому USB-пути. Два одинаковых устройства, подключённых в
разные порты, остаются отдельными объектами при сканировании.

Класс определяется по udev-свойствам и Linux input capability bitmap, а не
только по названию. Неизвестные устройства получают категорию `other-hid` и
всегда требуют явного подтверждения в интерактивном режиме.

## Udev и права доступа

Для разрешённого устройства генерируется правило следующего вида:

```udev
KERNEL=="hidraw*", ATTRS{idVendor}=="373e", ATTRS{idProduct}=="001e", TAG+="uaccess"
```

Файл правил: `/etc/udev/rules.d/70-hidpass.rules`.

Состояние выбранных устройств хранится в `/etc/hidpass/devices.json`.

После изменения выполняются:

```bash
udevadm control --reload-rules
udevadm trigger
```

Если ACL не обновился, переподключите устройство или донгл физически:
`uaccess` не всегда полностью пересчитывается одним `udevadm trigger`.

`TAG+="uaccess"` выдаёт доступ активному пользователю локального seat через
systemd-logind. Для headless-систем и удалённых сессий поведение может
отличаться. Bluetooth HID без USB VID/PID ancestry в текущей версии не
настраивается.

## Безопасность

`hidpass` не делает бинарник setuid-root и не требует запускать весь CLI через
`sudo`. Сканирование и чтение выполняются обычным пользователем; права
повышаются только для фиксированных операций `add`, `remove` и `apply`.

Проверяются следующие условия:

- privileged helper — обычный файл без setuid-бита;
- файл не должен быть group/world-writable;
- VID/PID нормализуются и валидируются;
- privileged payload ограничен по размеру и количеству устройств;
- правила создаются только для выбранных VID/PID;
- security HID исключаются из `auto`, включая `auto --yes`.

Явное `hidpass allow VID:PID` остаётся доступным для пользователя, который
осознанно настраивает необычное устройство.

## Структура проекта

```text
cmd/hidpass/        точка входа CLI
internal/app/       команды и пользовательский workflow
internal/discovery/ поиск hidraw, udev/sysfs fallback и deduplication
internal/classify/  классификация и security policy
internal/model/     общие валидируемые типы данных
internal/state/     атомарное хранение devices.json
internal/udev/      генерация правил, запись и reload
internal/privilege/ pkexec/sudo и защита privileged helper
```

## Тесты

Покрыты parsing `udevadm` properties, sysfs fallback, symlink resolution,
дедупликация hidraw-узлов, нормализация VID/PID, генерация безопасных rules,
state-файл, privilege escalation, классификация устройств и исключение
security-устройств.

Отдельный regression-тест проверяет старую проблему с обходом symlink-ов в
`/sys/bus/usb/devices`.

```bash
go test ./...
go vet ./...
```

## English summary

`hidpass` is a Linux CLI that discovers configurable USB HID/WebHID devices
through `/dev/hidraw*`, `udevadm`, and a sysfs fallback. It deduplicates HID
interfaces, classifies devices using udev properties and input capabilities,
and generates narrow `TAG+="uaccess"` rules for selected VID/PID pairs.

The tool keeps scanning unprivileged and elevates only state/rule writes via
`pkexec` or `sudo`. It never uses `MODE="0666"`, excludes security keys and
hardware wallets from automatic approval, and includes diagnostics and
regression tests for symlink-heavy Linux sysfs layouts.

## Лицензия

Лицензия пока не добавлена. Перед публичным релизом выберите и добавьте
подходящую лицензию в файл `LICENSE`.
