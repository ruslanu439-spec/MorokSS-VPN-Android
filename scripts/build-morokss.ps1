param(
    [ValidateSet("arm64-v8a", "armeabi-v7a", "x86_64", "x86")]
    [string]$Abi = "arm64-v8a"
)

$ErrorActionPreference = "Stop"
$repository = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repository "third_party\morokss"
$sdk = if ($env:ANDROID_SDK_ROOT) { $env:ANDROID_SDK_ROOT } else { Join-Path $env:LOCALAPPDATA "Android\Sdk" }
$ndk = Get-ChildItem (Join-Path $sdk "ndk") -Directory |
    Sort-Object Name -Descending |
    Select-Object -First 1 -ExpandProperty FullName
$toolchain = Join-Path $ndk "toolchains\llvm\prebuilt\windows-x86_64\bin"
$targets = @{
    "arm64-v8a"   = @{ Arch = "arm64"; Arm = "";  Cc = "aarch64-linux-android26-clang.cmd" }
    "armeabi-v7a" = @{ Arch = "arm";   Arm = "7"; Cc = "armv7a-linux-androideabi26-clang.cmd" }
    "x86_64"      = @{ Arch = "amd64"; Arm = "";  Cc = "x86_64-linux-android26-clang.cmd" }
    "x86"         = @{ Arch = "386";   Arm = "";  Cc = "i686-linux-android26-clang.cmd" }
}
$target = $targets[$Abi]
$output = Join-Path $repository "core\src\main\jniLibs\$Abi\libmorokss.so"
New-Item -ItemType Directory -Force -Path (Split-Path $output) | Out-Null

$previous = @{
    GOOS = $env:GOOS
    GOARCH = $env:GOARCH
    GOARM = $env:GOARM
    CGO_ENABLED = $env:CGO_ENABLED
    CC = $env:CC
}
try {
    $env:GOOS = "android"
    $env:GOARCH = $target.Arch
    $env:CGO_ENABLED = "1"
    $env:CC = Join-Path $toolchain $target.Cc
    if ($target.Arm) { $env:GOARM = $target.Arm } else { Remove-Item Env:GOARM -ErrorAction SilentlyContinue }
    Push-Location $source
    try {
        go build -buildmode=pie -trimpath -ldflags="-s -w" -o $output ".\cmd\morokss-client"
        if ($LASTEXITCODE -ne 0) { throw "MorokSS build failed with exit code $LASTEXITCODE" }
    } finally {
        Pop-Location
    }
    Write-Host "Built $output"
} finally {
    foreach ($name in $previous.Keys) {
        if ($null -eq $previous[$name]) {
            Remove-Item "Env:$name" -ErrorAction SilentlyContinue
        } else {
            Set-Item "Env:$name" $previous[$name]
        }
    }
}
