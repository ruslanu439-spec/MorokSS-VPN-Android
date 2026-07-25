# MorokSS VPN для Android

Это форк официального Shadowsocks Android. В него встроен транспорт MorokSS.
Исходник приложения взят из
[shadowsocks/shadowsocks-android](https://github.com/shadowsocks/shadowsocks-android),
а исходник транспорта подключён в `third_party/morokss`.

## Как подключиться

1. Открой приложение.
2. Нажми `+`.
3. Выбери «Вставить JSON MorokSS».
4. Вставь весь JSON, который выдал сервер.
5. Сохрани профиль и включи VPN.

JSON можно также открыть как файл или скопировать в буфер и выбрать обычный импорт.
Приложение само достанет настройки Shadowsocks, endpoint, TLS hostname и секрет.

## Что происходит внутри

`ss-local` принимает трафик Android как обычный Shadowsocks-клиент. Но вместо
прямого соединения с сервером он отправляет TCP и UDP на локальный MorokSS.
MorokSS заворачивает поток в выбранный TLS-профиль и транспорт, а затем идёт на
один из endpoint сервера.

Исходящие сокеты MorokSS передаются в Android `VpnService.protect()`. Поэтому
они не попадают обратно в TUN и VPN не зацикливается. Секрет передаётся процессу
через переменную окружения и не виден в командной строке.

## Сборка

Нужны JDK 17+, Android SDK 36, NDK 27, Rust и Go 1.24+.

```powershell
git clone --recurse-submodules https://github.com/ruslanu439-spec/MorokSS-VPN-Android.git
cd MorokSS-VPN-Android
./scripts/build-morokss.ps1 arm64-v8a
./gradlew.bat -PTARGET_ABI=arm64 :mobile:assembleDebug
```

На Linux вместо PowerShell используй `./scripts/build-morokss.sh arm64-v8a` и
`./gradlew`.

## Ограничения

Один IP всё равно можно заблокировать целиком. Автовыбор помогает только пока
в конфиге есть хотя бы один доступный endpoint и сервер нормально отвечает.
Ошибку сети нельзя со стопроцентной точностью отличить от блокировки.

Сейчас готова ARM64-сборка. Это большинство современных Android-телефонов.
Перед стабильным релизом ещё нужны тесты на реальных сетях разных операторов.
