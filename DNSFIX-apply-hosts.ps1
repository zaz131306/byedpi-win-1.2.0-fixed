# DNSFIX-apply-hosts.ps1 — переносит подготовленный Python'ом файл hosts на место.
#
# Зачем отдельный шаг с UAC: Python умеет всё, кроме одного — писать в
# C:\Windows\System32\drivers\etc\hosts без прав администратора. Поэтому Python
# готовит ЦЕЛЫЙ новый файл hosts (чужие строки сохранены, свой блок между меток,
# перевод строк родной), а здесь происходит только резервная копия и копирование.
#
# Почему так, а не «перезапустить весь .bat от админа»: при перезапуске через UAC
# окно живёт своей жизнью и закрывается мгновенно, а python.exe из Microsoft Store
# в повышенном контексте часто не находится вовсе (алиас WindowsApps). Человек
# видит мелькнувшее окно и ничего не понимает — ровно тот сбой, который этот
# скрипт призван исключить. Здесь весь вывод остаётся в обычном окне, а UAC
# запрашивается на одно короткое действие.
#
# Запуск:  powershell -NoProfile -ExecutionPolicy Bypass -File DNSFIX-apply-hosts.ps1 -Staged "ПУТЬ"
# Коды возврата: 0 успех, 2 нет прав, 3 нет файла, 4 не скопировалось

param([string]$Staged = "")

$ErrorActionPreference = 'Stop'

function Fail([int]$code, [string]$msg) {
    Write-Host ""
    Write-Host "[hosts] $msg"
    Write-Host ""
    exit $code
}

if (-not $Staged) { Fail 3 "Не передан путь к подготовленному файлу." }
if (-not (Test-Path -LiteralPath $Staged)) { Fail 3 "Подготовленный файл не найден: $Staged" }

$root = $env:SystemRoot
if (-not $root) { $root = 'C:\Windows' }
$hosts = Join-Path $root 'System32\drivers\etc\hosts'
$dir = Split-Path -Parent $hosts

# --- права администратора: проверяем, а не надеемся ---
$admin = $false
try {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    $admin = $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }

if (-not $admin) {
    # Перезапускаем САМИ СЕБЯ с UAC. Окно при этом на мгновение появится и
    # закроется — это нормально, весь вывод идёт в родительском окне.
    try {
        $psi = @{
            FilePath         = 'powershell.exe'
            ArgumentList     = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File',
                                 "`"$PSCommandPath`"", '-Staged', "`"$Staged`"")
            WorkingDirectory = $PSScriptRoot
            Verb             = 'RunAs'
        }
        $p = Start-Process @psi -PassThru -Wait
        exit $p.ExitCode
    } catch {
        Fail 2 "Права не выданы (окно UAC отклонено или недоступно)."
    }
}

# --- резервная копия ---
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$bak = "$hosts.dnsfix-bak-$stamp"
try {
    if (Test-Path -LiteralPath $hosts) {
        Copy-Item -LiteralPath $hosts -Destination $bak -Force
        Write-Host "[hosts] копия прежнего файла: $bak"
    }
} catch {
    Write-Host "[hosts] ВНИМАНИЕ: копию сделать не удалось ($($_.Exception.Message))"
}

# --- перенос ---
try {
    Copy-Item -LiteralPath $Staged -Destination $hosts -Force
} catch {
    Fail 4 "Скопировать на место не удалось: $($_.Exception.Message)"
}

# --- проверка, что записалось именно то, что хотели ---
try {
    $a = (Get-FileHash -LiteralPath $Staged -Algorithm SHA256).Hash
    $b = (Get-FileHash -LiteralPath $hosts -Algorithm SHA256).Hash
    if ($a -ne $b) { Fail 4 "Файл записан, но содержимое не совпало с подготовленным." }
} catch {
    Write-Host "[hosts] сверить хэш не удалось: $($_.Exception.Message)"
}

# --- сброс кэша DNS ---
$flush = & ipconfig /flushdns 2>&1 | Out-String
Write-Host "[hosts] записано: $hosts"
Write-Host ("[hosts] кэш DNS: " + ($flush -replace "\s+", " ").Trim())
exit 0
