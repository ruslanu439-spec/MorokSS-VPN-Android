# MorokSS VPN для Android

[![Android build](https://github.com/ruslanu439-spec/MorokSS-VPN-Android/actions/workflows/android-build.yml/badge.svg)](https://github.com/ruslanu439-spec/MorokSS-VPN-Android/actions/workflows/android-build.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](https://www.gnu.org/licenses/gpl-3.0)

Это готовый Android VPN-клиент с профилями, QR, выбором приложений и поддержкой
TCP/UDP. Внутрь добавлен наш транспорт MorokSS.

Конфиг можно открыть файлом, импортировать из буфера или вставить прямо в окно
«Вставить JSON MorokSS». Подробная инструкция лежит в [MOROKSS.md](MOROKSS.md).

Но важно понимать ограничение: приложение не может гарантировать обход любой
блокировки. Если заблокированы все IP из конфига, нужен новый endpoint.

## Что нового в 0.4.0-alpha4

Клиент быстрее переходит на следующий endpoint при TLS-таймауте.
JSON теперь принимает список `endpoints`.

На некоторых мобильных сетях TLS подключается, но поток зависает после первых
16–20 КБ. Обычная проверка порта этого не видит.

Теперь MorokSS перед подключением прогоняет 96 КБ в обе стороны. Если вариант
не выдержал тест, приложение пробует другой TLS-профиль, транспорт или SNI.

Результаты хранятся отдельно для мобильного интернета и Wi-Fi. Сертификат
сервера проверяется даже при запасном SNI.

Это не гарантия от любой блокировки. Списки разрешённых SNI отличаются у
операторов, а заблокированный IP всё равно придётся заменить. Подробности есть
в [разборе мобильного DPI](third_party/morokss/docs/MOBILE_DPI.md).

Основа проекта — официальный
[Shadowsocks Android](https://github.com/shadowsocks/shadowsocks-android).
Мы сохраняем его лицензию GPL-3.0 и историю изменений.


### PREREQUISITES

* JDK 17+
* Android SDK
  - Android NDK
* Go 1.24+
* Rust with Android targets installed using `rustup target add armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android`

### BUILD

You can check whether the latest commit builds under UNIX environment by checking Travis status.

* Install prerequisites
* Clone the repo using `git clone --recurse-submodules <repo>` or update submodules using `git submodule update --init --recursive`
* Build it using Android Studio or gradle script

### CONTRIBUTING

If you are interested in contributing or getting involved with this project, please read the CONTRIBUTING page for more information.  The page can be found [here](https://github.com/shadowsocks/shadowsocks-android/blob/master/CONTRIBUTING.md).


### [TRANSLATE](https://discourse.shadowsocks.org/t/poeditor-translation-main-thread/30)
