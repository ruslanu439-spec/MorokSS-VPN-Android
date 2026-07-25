# MorokSS для Android

Android-приложение запускает нативный клиент MorokSS в foreground service и слушает TCP/UDP на
`127.0.0.1:8389`. После этого Amnezia или другой клиент Shadowsocks подключается к локальному адресу.

## Как пользоваться

1. Установи APK и добавь JSON-профиль MorokSS: выбери файл или вставь весь JSON вручную.
2. Нажми «Запустить MorokSS» и разреши уведомления.
3. Нажми «Скопировать ss:// для Amnezia».
4. В Amnezia импортируй ссылку из буфера обмена.
5. В разделении трафика Amnezia исключи приложение MorokSS из VPN.
6. Подключись и не отключай уведомление MorokSS.

Исключение приложения важно. Без него исходящее соединение MorokSS может попасть обратно в VPN и
зациклиться.

Профиль хранится в закрытом хранилище приложения и шифруется ключом из Android Keystore. Секреты не
вшиты в APK.

В окне ручного ввода можно зажать поле и выбрать обычную вставку Android или нажать
«Вставить из буфера». Неверный или неполный JSON приложение не сохранит.

## Сборка

Нужны Go 1.24+, JDK 17 и Android SDK 35.

На Windows:

```powershell
.\scripts\build-android.ps1
cd android
.\gradlew.bat assembleDebug
```

На Linux/macOS:

```bash
./scripts/build-android.sh
cd android
./gradlew assembleDebug
```

APK появится в `android/app/build/outputs/apk/debug/`.
