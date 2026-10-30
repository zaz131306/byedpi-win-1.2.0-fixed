# WL-check-download-python.ps1
# Скачивает портативный (embeddable) Python в %TEMP%\wlpy и печатает путь к python.exe.
# Нужен ТОЛЬКО если на машине нет Python — WL-check.bat вызывает его сам.
# Ничего в систему не ставит, реестр не трогает, PATH не меняет: распаковка в %TEMP%.
#
# Ручной запуск:
#   powershell -NoProfile -ExecutionPolicy Bypass -File WL-check-download-python.ps1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ver  = '3.12.8'
$url  = "https://www.python.org/ftp/python/$ver/python-$ver-embed-amd64.zip"
$dest = Join-Path $env:TEMP 'wlpy'
$zip  = Join-Path $env:TEMP 'wlpy.zip'
$exe  = Join-Path $dest 'python.exe'

# Если уже скачан — просто возвращаем путь, повторно не качаем.
if (Test-Path $exe) {
    Write-Output $exe
    exit 0
}

Write-Host "[WL-check] Качаю портативный Python $ver (~11 МБ)..." -ForegroundColor DarkGray
try {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
} catch {
    # Запасное зеркало
    Invoke-WebRequest -Uri "https://www.nuget.org/api/v2/package/python/$ver" -OutFile $zip -UseBasicParsing
}

if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $dest -Force

# Embeddable-сборка по умолчанию не видит site-packages и не даёт ставить пакеты.
# WL-check.py использует ТОЛЬКО стандартную библиотеку, но раскомментируем site,
# чтобы питон вёл себя привычно.
$pth = Get-ChildItem -Path $dest -Filter 'python*._pth' | Select-Object -First 1
if ($pth) {
    $lines = Get-Content $pth.FullName | Where-Object { $_ -ne '#import site' }
    if ($lines -notcontains 'import site') { $lines += 'import site' }
    Set-Content -Path $pth.FullName -Value $lines -Encoding ascii
}

Remove-Item $zip -Force -ErrorAction SilentlyContinue

if (-not (Test-Path $exe)) {
    Write-Host '[WL-check] Не удалось распаковать Python.' -ForegroundColor Red
    exit 1
}

Write-Host "[WL-check] Готово: $exe" -ForegroundColor DarkGray
Write-Output $exe
exit 0
