# hidpass

Безопасная Linux-утилита, которая находит подключённые USB/HID-устройства и
создаёт для выбранных устройств точечные udev-правила доступа к `/dev/hidraw*`.

Подходит для клавиатур, мышей, Stream Deck и других конфигураторов WebHID.
Ручной поиск VID/PID и запуск всей программы через `sudo` не нужны.

![Пример работы hidpass](docs/screenshots/hidpass-cli.png)

## Установка

### Готовый бинарник

1. Откройте [последний Release](https://github.com/MixaDoDs/hidpass/releases/latest).
2. Скачайте `hidpass-linux-amd64`.
3. **Проверьте SHA-256 до `sudo install`** (v0.1.0):

   ```bash
   sha256sum hidpass-linux-amd64
   ```

   Ожидаемое значение:

   ```
   843af2d74b2b5424d588d63ebfdf14c9d0f6ac31e2b6a6e25760ff5d5e9aabbb
   ```

   Если сумма не совпадает — не устанавливайте файл.
4. Установите:

   ```bash
   chmod +x hidpass-linux-amd64
   sudo install -m 0755 hidpass-linux-amd64 /usr/local/bin/hidpass
   ```

5. Проверьте установку:

   ```bash
   hidpass doctor
   hidpass scan
   ```

### Сборка из исходников

```bash
git clone https://github.com/MixaDoDs/hidpass.git
cd hidpass
go test ./...
make build
sudo make install
```

`make build` проставляет версию и commit через `-ldflags`. `make install`
кладёт бинарник в `/usr/local/bin/hidpass` и polkit-политику
`org.hidpass.apply` в `/usr/share/polkit-1/actions/`.

## Быстрый старт

```bash
hidpass scan
hidpass auto
```

`auto` покажет найденные устройства и спросит подтверждение для каждого.
Клавиатуры и мыши по умолчанию **не** добавляются (`[y/N]`): hidraw на
клавиатуре — это сырые HID-репорты на весь seat (кейлоггинг и инъекция
клавиш). Security-ключи (YubiKey/FIDO и т.п.) пропускаются. Запись правил
выполняется через стандартное окно Polkit (`pkexec`) или через `sudo` как
запасной вариант. Само сканирование root-доступа не требует.

Полезные команды:

```bash
hidpass scan --debug   # подробная диагностика udev/sysfs
hidpass list           # разрешённые устройства
hidpass auto --yes     # добавить все подходящие устройства (с предупреждением для клавиатур/мышей)
hidpass remove 373e:001e
hidpass apply
hidpass doctor
hidpass uninstall      # снять правила и /etc/hidpass/devices.json
```

Подробное описание архитектуры, безопасности, тестов и udev находится в
[расширенной документации](docs/README.ru.md).

## Безопасность

`hidpass` создаёт только точечные правила с `TAG+="uaccess"` и не использует
глобальный `MODE="0666"`. YubiKey/FIDO, Ledger, Trezor, Nitrokey, Google Titan,
Feitian и другие security-устройства не добавляются автоматически; явный
`hidpass allow VID:PID` остаётся возможным.

Состояние хранится в `/etc/hidpass/devices.json`, правила — в
`/etc/udev/rules.d/70-hidpass.rules` (не в `/run`: это постоянный путь, udev
подхватывает его после перезагрузки). `udevadm trigger` ограничен subsystem
`hidraw`.

## Лицензия

[MIT](LICENSE)
