# Подробная документация hidpass

## Что делает утилита

`hidpass` обнаруживает USB/HID-устройства, которым нужен доступ к
`/dev/hidraw*` для WebHID и фирменных конфигураторов. Для выбранных VID/PID
генерируется правило:

```udev
KERNEL=="hidraw*", ATTRS{idVendor}=="373e", ATTRS{idProduct}=="001e", TAG+="uaccess"
```

Глобальный `MODE="0666"` не используется.

## Команды

| Команда | Назначение |
| --- | --- |
| `hidpass scan` | Найти и классифицировать устройства |
| `hidpass scan --debug` | Показать udev/sysfs evidence для каждого hidraw |
| `hidpass list` | Показать сохранённые VID:PID |
| `hidpass auto` | Интерактивно выбрать устройства |
| `hidpass auto --yes` | Автоматически выбрать подходящие устройства |
| `hidpass allow VID:PID` | Явно добавить устройство |
| `hidpass remove VID:PID` | Удалить устройство |
| `hidpass apply` | Пересобрать rules и перезагрузить udev |
| `hidpass doctor` | Проверить окружение |
| `hidpass version` | Показать версию |

После reload/trigger иногда требуется физически переподключить устройство или
донгл, чтобы ACL `uaccess` обновился. То же самое действует и в обратную
сторону: udev заново применяет `uaccess`, но никогда его не снимает, поэтому
после `remove` уже выданный ACL сохраняется на подключённой ноде до
переподключения устройства.

## Обнаружение и дедупликация

Сканирование начинается с `/dev/hidraw*`, затем запускается:

```bash
udevadm info --query=property --name=/dev/hidrawN
```

Если udev не сообщает VID/PID, программа разрешает
`/sys/class/hidraw/hidrawN/device` и поднимается вверх по sysfs до родителя с
`idVendor` и `idProduct`.

`hidpass` не обходит `/sys/bus/usb/devices`: там много symlink-ов, которые
`filepath.WalkDir` не посещает. Несколько HID-интерфейсов одного физического
устройства объединяются по VID/PID и родительскому USB-пути.

Bluetooth-устройства пропускаются. Их недостаточно отсеять по `ID_BUS`:
hidraw-правила udev импортируют `usb_id`, если USB-устройством является любой
предок, поэтому устройство, спаренное с USB-донглом, сообщает `ID_BUS=usb` и
VID:PID *донгла*. Правило для такого ID выдало бы доступ ко всем устройствам
за этим адаптером, поэтому транспорт читается из имени каталога HID-устройства
(`BUS:VID:PID.INSTANCE`, `0003` — USB), а остальные шины попадают в
диагностику.

Классификация использует `ID_INPUT_*` и Linux input capability bitmaps:

```text
keyboard  mouse  streamdeck  touchpad  tablet  joystick  other-hid
```

На практике решают именно bitmaps: сами hidraw-ноды почти никогда не несут
свойств `ID_INPUT_*` — их выставляет udev на соседних input-устройствах.
Ядро печатает bitmap как машинные слова через `%lx` без ведущих нулей,
старшим словом вперёд, поэтому нулевой бит лежит в самом правом поле.

Неизвестные `other-hid` требуют подтверждения. Security-устройства
(YubiKey/FIDO, Ledger, Trezor, Nitrokey и похожие) пропускаются в `auto`,
включая `auto --yes`; осознанный `allow VID:PID` остаётся доступен.

## Привилегии

Сканирование и чтение работают от обычного пользователя. Только операции
`add`, `remove` и `apply` запускаются через `pkexec`, а при его отсутствии —
через `sudo`. Бинарник не является setuid-root.

Проверяются обычный тип файла, отсутствие setuid и отсутствие
group/world-writable разрешений. Владельцем должен быть `root` или сам
вызывающий пользователь: бинарник третьего пользователя тот может переписать и
получить root через чужую аутентификацию. Пользовательский бинарник `0755`
допустим; его не нужно делать владельцем `root`.

Привилегированный помощник задаёт собственный `PATH`: `sudo` без
`secure_path` передаёт `PATH` вызывающего, а от него зависит, какой `udevadm`
выполнится от root.

## Файлы системы

```text
/etc/hidpass/devices.json
/etc/udev/rules.d/70-hidpass.rules
```

После изменения правил выполняются:

```bash
udevadm control --reload-rules
udevadm trigger --subsystem-match=hidraw
```

`trigger` ограничен подсистемой `hidraw`: без фильтра udev переотправляет
uevent для всех устройств системы.

## Разработка

```bash
go test ./...
go vet ./...
go build -trimpath -o hidpass ./cmd/hidpass
```

Тесты покрывают parsing `udevadm`, sysfs fallback, symlink resolution,
дедупликацию, нормализацию VID/PID, генерацию rules, state, privilege logic,
классификацию и исключение security-устройств. Есть regression-тест для
старой ошибки обхода symlink-ов в `/sys/bus/usb/devices`.
