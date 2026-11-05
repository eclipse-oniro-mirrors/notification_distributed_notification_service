@echo off
rem One-shot WinUSB driver install for Rockchip Loader/Maskrom device (VID_2207 PID_350A / PID_5000)
rem Uses wdi-simple (libwdi, the engine behind Zadig): auto-generates INF + self-signed certificate,
rem imports the cert to Root/TrustedPublisher and installs the driver package. No Windows SDK needed.
rem Run as Administrator on Windows (deployed together with the flash toolchain, see skill references/flash-env.md §0/§1)
rem Requires bin\wdi-simple.exe + bin\libusb-1.0.dll at one of the discovery locations
rem ($WIN_DIR\bin\ by convention) - build on server: bash bin/ensure_bin.sh
cd /d %~dp0
net session >nul 2>&1 || (echo [ERROR] please run as Administrator & exit /b 1)
if not exist bin\wdi-simple.exe (
  echo [ERROR] missing bin\wdi-simple.exe - build it first on the server: bash bin\ensure_bin.sh
  echo         ^(then deploy bin\ contents to a discovery location ($WIN_DIR\bin\ by convention), see references/flash-env.md
  exit /b 1
)
echo [1/2] installing WinUSB driver for Rockchip Loader ^(VID_2207 PID_350A^) ...
bin\wdi-simple.exe --vid 0x2207 --pid 0x350a --type 0 --name "Rockchip Loader" --silent || exit /b 1
echo [2/2] installing WinUSB driver for Rockchip Maskrom ^(VID_2207 PID_5000^) ...
bin\wdi-simple.exe --vid 0x2207 --pid 0x5000 --type 0 --name "Rockchip Maskrom" --silent || exit /b 1
echo [OK] done. Put board into Loader mode (hdc shell "reboot loader" or RECOVERY+RESET), then run flash_rk3568.bat
