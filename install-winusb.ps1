# =============================================================================
#  install-winusb.ps1  --  给 Sony VGP-URM10 绑定 Windows 自带的 WinUSB 驱动
#
#  推荐用法（一条命令，自动提权；URL 由网页按 document.location 生成）：
#
#      powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:VGP_URL='<脚本URL>'; irm $env:VGP_URL | iex"
#
#  也可以直接下载本文件后运行（此时不需要 VGP_URL，脚本自带 INF）：
#
#      powershell -ExecutionPolicy Bypass -File install-winusb.ps1
#
#  为什么需要：Chrome / Edge 的 WebUSB 只能看到被通用驱动 WinUSB 接管的设备。
#              本设备没在描述符里自我声明 WinUSB，所以干净的 Windows 不会自动绑定。
#  说明：不安装任何厂商内核驱动，只是把设备交给 Windows 自带的 winusb.sys。
# =============================================================================

$ErrorActionPreference = 'Stop'

# ---- 需要管理员权限：用 VGP_URL 重新拉取自己并在提权会话里执行 ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
             [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
  if (-not $env:VGP_URL) {
    Write-Host '  Not elevated and $env:VGP_URL is empty.' -ForegroundColor Red
    Write-Host '  Please run this one-liner from the web page instead:' -ForegroundColor Yellow
    Write-Host '    powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:VGP_URL=''<script url>''; irm $env:VGP_URL | iex"'
    Write-Host ''
    Read-Host '  Press Enter to close'
    exit 1
  }
  Write-Host '  Requesting administrator rights...' -ForegroundColor Yellow
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @(
      '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', 'irm $env:VGP_URL | iex')
  exit
}

# ---- 内嵌的最小 INF（等价于 Sony 原厂驱动在 Win8.1+ 上做的事）----
$infLines = @(
  '[Version]'
  'Signature   = "$Windows NT$"'
  'Class       = USBDevice'
  'ClassGuid   = {88bae032-5a81-49f0-bc3d-a4ff138216d6}'
  'Provider    = %ProviderName%'
  'DriverVer   = 09/23/2026,1.0.0.0'
  ''
  '[Manufacturer]'
  '%ProviderName% = Standard, NTamd64'
  ''
  '[Standard.NTamd64]'
  '%DeviceName% = USB_Install, USB\VID_054C&PID_0883'
  ''
  '[USB_Install]'
  'Include = winusb.inf'
  'Needs   = WINUSB.NT'
  ''
  '[USB_Install.Services]'
  'Include = winusb.inf'
  'Needs   = WINUSB.NT.Services'
  ''
  '[USB_Install.HW]'
  'AddReg = Dev_AddReg'
  ''
  '[Dev_AddReg]'
  'HKR,,DeviceInterfaceGUIDs,0x10000,"{AC2C0F91-97D5-452D-8F89-E055C8C498A4}"'
  ''
  '[Strings]'
  'ProviderName = "VGP-URM10 (WinUSB)"'
  'DeviceName   = "Sony VGP-URM10 USB IR Adapter (WinUSB)"'
)

$infPath = Join-Path $env:TEMP 'vgp-urm10-winusb.inf'
Set-Content -Path $infPath -Value ($infLines -join "`r`n") -Encoding ASCII

Write-Host ''
Write-Host '  Sony VGP-URM10  ->  WinUSB driver helper' -ForegroundColor Cyan
Write-Host '  INF written to: ' -NoNewline; Write-Host $infPath -ForegroundColor Gray
Write-Host ''
Write-Host '  Installing (pnputil /add-driver ... /install) ...' -ForegroundColor Yellow
$out = & pnputil.exe /add-driver $infPath /install 2>&1
$out | ForEach-Object { Write-Host ('    ' + $_) }
$rc = $LASTEXITCODE

Write-Host ''
if ($rc -eq 0) {
  Write-Host '  [OK] Done.' -ForegroundColor Green
  Write-Host '       If the adapter is already plugged in: unplug it, plug it back,'
  Write-Host '       then reload the web page and click "Connect device".'
} else {
  Write-Host "  [WARN] pnputil exited with code $rc" -ForegroundColor Red
  Write-Host '         Windows x64 may refuse an unsigned INF. Alternatives:'
  Write-Host '           1) install Sony original driver package (EP0000311568.exe)'
  Write-Host '           2) use Zadig (https://zadig.akeo.ie) and choose WinUSB'
}
Write-Host ''
Write-Host '  Verify afterwards (PowerShell):'
Write-Host '    Get-ItemProperty ''HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_054C&PID_0883\*'' | Select Service'
Write-Host '    -> should print:  Service : WINUSB'
Write-Host ''
Read-Host '  Press Enter to close'
