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
| `hidpass uninstall` | Удалить rules и `/etc/hidpass/devices.json` |
| `hidpass doctor` | Проверить окружение |
| `hidpass version` | Показать версию |

После reload/trigger иногда требуется физически переподключить устройство или
донгл, чтобы ACL `uaccess` обновился. То же самое действует и в обратную
сторону: udev заново применяет `uaccess`, но никогда его не снимает, поэтому
после `remove` уже выданный ACL сохраняется на подключённой ноде до
переподключения устройства.

`auto` для клавиатур и мышей спрашивает `[y/N]` и печатает предупреждение:
hidraw на клавиатуре — сырые репорты на весь seat (кейлоггинг/инъекция).
`--yes` всё равно может их добавить, но предупреждение остаётся. FIDO/security
ключи в `auto` пропускаются; `allow VID:PID` — явный override.

## Обнаружение и дедупликация

Сканирование начинается с `/dev/hidraw*`, затем запускается:

```bash
udevadm info --query=property --name=/dev/hidrawN
```

Если udev не сообщает VID/PID, программа разрешает
`/sys/class/hidraw/hidrawN/device` и поднимается вверх по sysfs до родителя с
`idVendor` и `idProduct`.

Пустой `ID_BUS` **не** считается USB сам по себе. Устройство принимается как
USB, если `ID_BUS=usb` или найден USB-родитель в sysfs. Иначе узел
пропускается как неизвестная шина.

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
(YubiKey/FIDO, Ledger, Trezor, Nitrokey, Google Titan, Feitian и похожие)
пропускаются в `auto`, включая `auto --yes`; осознанный `allow VID:PID`
остаётся доступен. Привилегированный helper повторно проверяет deny-list на
пути `add`/`auto`, чтобы подделанный payload не протащил security-ключ.

## Привилегии

Сканирование и чтение работают от обычного пользователя. Только операции
`add`, `allow`, `remove`, `apply` и `uninstall` запускаются через `pkexec`,
а при его отсутствии — через `sudo`. Бинарник не является setuid-root.

Проверяются обычный тип файла, отсутствие setuid и отсутствие
group/world-writable разрешений на самом файле, а также отсутствие
world-writable каталога (в том числе бинарник прямо в `/tmp`). Владельцем
должен быть `root` или сам вызывающий пользователь: бинарник третьего
пользователя тот может переписать и получить root через чужую аутентификацию.
Пользовательский бинарник `0755` в своём каталоге допустим для разработки;
доверенный путь — root-owned `/usr/local/bin/hidpass`.

Привилегированный помощник задаёт собственный `PATH`: `sudo` без
`secure_path` передаёт `PATH` вызывающего, а от него зависит, какой `udevadm`
выполнится от root.

Polkit-действие `org.hidpass.apply` описывает, что hidpass записывает
udev-правила hidraw. Файл политики: `contrib/polkit/org.hidpass.policy`.

## Файлы системы

```text
/etc/hidpass/devices.json
/etc/udev/rules.d/70-hidpass.rules
/usr/share/polkit-1/actions/org.hidpass.policy
```

Правила пишутся атомарно (temp + rename, режим `0644`) в
`/etc/udev/rules.d/`, **не** в `/run/udev/rules.d`. После перезагрузки udev
сам загружает `/etc/udev/rules.d`, поэтому правила не пропадают, пока файл
на месте. hidpass не ставит tmpfiles.d и не нужен systemd oneshot только
ради persistence.

Установка конфигурации транзакционная: сначала генерируются rules, затем
записываются rules, затем state. Если запись rules не удалась, `devices.json`
не уезжает вперёд.

После изменения правил выполняются:

```bash
udevadm control --reload-rules
udevadm trigger --subsystem-match=hidraw --action=change
```

`trigger` ограничен подсистемой `hidraw`: без фильтра udev переотправляет
uevent для всех устройств системы. `--action=change` переприменяет правила
без полного re-enumerate.

`hidpass doctor` проверяет, что rules-файл в `/etc` (не в `/run`), что он
есть, если устройства уже настроены, и предупреждает, если logind/seat
скорее всего отсутствует или у `/dev/hidraw*` нет ACL `uaccess` при
существующих правилах.

`hidpass uninstall` удаляет rules-файл, `devices.json` и пустой
`/etc/hidpass`, затем делает тот же узкий trigger.

## Разработка

```bash
go test ./...
go vet ./...
make build
./bin/hidpass version
```

Тесты покрывают parsing `udevadm`, sysfs fallback, symlink resolution,
дедупликацию, пустой `ID_BUS`, нормализацию VID/PID, генерацию rules,
узкий trigger, транзакционный install, state, privilege logic,
классификацию, расширенный security VID deny-list, default-deny для
клавиатур в `auto` и uninstall.
