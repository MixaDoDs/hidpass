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
донгл, чтобы ACL `uaccess` обновился.

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

Классификация использует `ID_INPUT_*` и Linux input capability bitmaps:

```text
keyboard  mouse  streamdeck  touchpad  tablet  joystick  other-hid
```

Неизвестные `other-hid` требуют подтверждения. Security-устройства
(YubiKey/FIDO, Ledger, Trezor, Nitrokey и похожие) пропускаются в `auto`,
включая `auto --yes`; осознанный `allow VID:PID` остаётся доступен.

## Привилегии

Сканирование и чтение работают от обычного пользователя. Только операции
`add`, `remove` и `apply` запускаются через `pkexec`, а при его отсутствии —
через `sudo`. Бинарник не является setuid-root.

Проверяются обычный тип файла, отсутствие setuid и отсутствие
group/world-writable разрешений. Пользовательский бинарник `0755` допустим;
его не нужно делать владельцем `root`.

## Файлы системы

```text
/etc/hidpass/devices.json
/etc/udev/rules.d/70-hidpass.rules
```

После изменения правил выполняются:

```bash
udevadm control --reload-rules
udevadm trigger
```

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
