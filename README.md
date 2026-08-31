# hidpass

Linux не даёт браузеру и десктопным конфигураторам доступ к `/dev/hidraw*`.
Из-за этого VIA, прошивалки клавиатур, Stream Deck и макропады просто
не видят устройство.

hidpass смотрит, что воткнуто по USB, спрашивает что разрешить и пишет
точечное udev-правило. Доступ получает твоя сессия, не весь компьютер.

Работает с любым USB HID, у которого есть hidraw: клавиатуры (QMK/VIA,
NuPhy, Keychron, кастомы), мыши с софтом, Stream Deck, макропады,
аудиоинтерфейсы с HID-кнопками. Bluetooth не трогает. YubiKey, FIDO,
Ledger и прочие ключи в `auto` пропускает сам.

![hidpass auto](docs/screenshots/hidpass-auto.png)

## Установка

Скачай `hidpass-linux-amd64` из [последнего релиза](https://github.com/MixaDoDs/hidpass/releases/latest).
SHA-256 написан в описании релиза — сверь, если не лень.

```bash
chmod +x hidpass-linux-amd64
sudo install -m 0755 hidpass-linux-amd64 /usr/local/bin/hidpass
hidpass doctor
```

Или из исходников: `git clone`, `make test`, `sudo make install`.

## Как пользоваться

Воткни устройство в USB.

```bash
hidpass scan    # что он видит
hidpass auto    # разрешить по одному
hidpass list    # что уже прописано
```

На каждый девайс вопрос `y`/`n`. Клавиатуру и мышь по умолчанию не добавит —
надо явно согласиться. Запись правил — обычное окно polkit.

Если в браузере после этого пусто — выдерни USB и воткни снова.

Убрать устройство: `hidpass remove VID:PID`.
Снять всё: `hidpass uninstall`.

[MIT](LICENSE) · [как внутри](docs/README.ru.md)
