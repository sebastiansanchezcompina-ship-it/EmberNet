@echo off
set ANDROID_NDK_HOME=C:\android-ndk-r27d
echo 🦀 Compilando Rust...
cargo ndk -t x86_64 build --release --lib

echo 🚚 Copiando libreria a Android Studio...
copy /Y "target\x86_64-linux-android\release\libember_core.so" "C:\Users\sanch\AndroidStudioProjects\EmberApp\app\src\main\jniLibs\x86_64\"

echo ✅ ¡Listo! Ahora solo dale al Play en Android Studio.