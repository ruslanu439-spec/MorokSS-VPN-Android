$ErrorActionPreference = "Stop"

$repository = Split-Path -Parent $PSScriptRoot
$jniRoot = Join-Path $repository "android\app\src\main\jniLibs"
$ndkRoot = $env:ANDROID_NDK_HOME
if (-not $ndkRoot) {
    $sdkRoot = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { Join-Path $env:LOCALAPPDATA "Android\Sdk" }
    $ndkRoot = Get-ChildItem (Join-Path $sdkRoot "ndk") -Directory -ErrorAction Stop |
        Sort-Object Name -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}
$toolchain = Join-Path $ndkRoot "toolchains\llvm\prebuilt\windows-x86_64\bin"

$targets = @(
    @{ Abi = "arm64-v8a"; GoArch = "arm64"; GoArm = ""; Compiler = "aarch64-linux-android26-clang.cmd" },
    @{ Abi = "armeabi-v7a"; GoArch = "arm"; GoArm = "7"; Compiler = "armv7a-linux-androideabi26-clang.cmd" },
    @{ Abi = "x86_64"; GoArch = "amd64"; GoArm = ""; Compiler = "x86_64-linux-android26-clang.cmd" },
    @{ Abi = "x86"; GoArch = "386"; GoArm = ""; Compiler = "i686-linux-android26-clang.cmd" }
)

foreach ($target in $targets) {
    $outputDirectory = Join-Path $jniRoot $target.Abi
    New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null

    $env:GOOS = "android"
    $env:GOARCH = $target.GoArch
    $env:CGO_ENABLED = "1"
    $env:CC = Join-Path $toolchain $target.Compiler
    if ($target.GoArm) {
        $env:GOARM = $target.GoArm
    } else {
        Remove-Item Env:GOARM -ErrorAction SilentlyContinue
    }

    $output = Join-Path $outputDirectory "libmorokss.so"
    go build -buildmode=pie -trimpath -ldflags="-s -w" -o $output "$repository\cmd\morokss-client"
    if ($LASTEXITCODE -ne 0) {
        throw "Go build failed for $($target.Abi) with exit code $LASTEXITCODE"
    }
    Write-Host "Built $($target.Abi): $output"
}
