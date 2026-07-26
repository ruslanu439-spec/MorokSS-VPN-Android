# MorokSS VPN для Android

[![Android build](https://github.com/ruslanu439-spec/MorokSS-VPN-Android/actions/workflows/android-build.yml/badge.svg)](https://github.com/ruslanu439-spec/MorokSS-VPN-Android/actions/workflows/android-build.yml)
[![License: GPL-3.0](https://img.shields.io/badge/license-GPL--3.0-orange.svg)](https://www.gnu.org/licenses/gpl-3.0)

Это готовый Android VPN-клиент с профилями, QR, выбором приложений и поддержкой
TCP/UDP. Внутрь добавлен наш транспорт MorokSS.

Конфиг можно открыть файлом, импортировать из буфера или вставить прямо в окно
«Вставить JSON MorokSS». Подробная инструкция лежит в [MOROKSS.md](MOROKSS.md).

Но важно понимать ограничение: приложение не может гарантировать обход любой
блокировки. Если заблокированы все IP из конфига, нужен новый endpoint.

## Что нового в 0.4.0-alpha2

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

## OPEN SOURCE LICENSES

<ul>
    <li>redsocks: <a href="https://github.com/shadowsocks/redsocks/blob/shadowsocks-android/README">APL 2.0</a></li>
    <li>libevent: <a href="https://github.com/shadowsocks/libevent/blob/master/LICENSE">BSD</a></li>
    <li>tun2socks: <a href="https://github.com/shadowsocks/badvpn/blob/shadowsocks-android/COPYING">BSD</a></li>
    <li>shadowsocks-rust: <a href="https://github.com/shadowsocks/shadowsocks-rust/blob/master/LICENSE">MIT</a></li>
    <li>libsodium: <a href="https://github.com/jedisct1/libsodium/blob/master/LICENSE">ISC</a></li>
    <li>OpenSSL: <a href="https://www.openssl.org/source/license-openssl-ssleay.txt">OpenSSL License</a></li>
</ul>


### LICENSE

Copyright (C) 2017 by Max Lv <<max.c.lv@gmail.com>>  
Copyright (C) 2017 by Mygod Studio <<contact-shadowsocks-android@mygod.be>>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
