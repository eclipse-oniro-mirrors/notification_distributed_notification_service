@echo off
rem RK3568 OpenHarmony full partition flash via rkdeveloptool (Loader mode required)
rem Usage: flash_rk3568.bat [images_dir] [rkdeveloptool_path]
rem   images_dir         default C:\Users\%USERNAME%\rk3568\images
rem   rkdeveloptool_path default %~dp0bin\rkdeveloptool.exe (支持服务器侧动态发现后传入)
rem Partition addresses from same-source parameter.txt - DO NOT edit casually
rem SAFETY: only proceeds when a REAL Loader device (Pid=0x350a) is present.
rem         NOTE rkdeveloptool mislabels the hdc device (Pid=0x5000) as "Maskrom" - never match on that label.
setlocal
set IMGDIR=%~1
if "%IMGDIR%"=="" set IMGDIR=C:\Users\%USERNAME%\rk3568\images
set RKT=%~2
if "%RKT%"=="" set RKT=%~dp0bin\rkdeveloptool.exe
if not exist "%RKT%" ( echo [ERROR] missing %RKT% - build it first on the server: bash bin/ensure_bin.sh & exit /b 1 )
if not exist "%~dp0bin\libusb-1.0.dll" ( echo [ERROR] missing %~dp0bin\libusb-1.0.dll - run: bash bin/ensure_bin.sh & exit /b 1 )
if not exist "%IMGDIR%" ( echo [ERROR] images dir not found: %IMGDIR% & exit /b 1 )
cd /d "%IMGDIR%"
"%RKT%" ld > "%TEMP%\rk_ld.txt" 2>&1
type "%TEMP%\rk_ld.txt"
findstr /c:"Pid=0x350a" "%TEMP%\rk_ld.txt" >nul || ( echo [ERROR] no REAL Loader device ^(Pid=0x350a^) found. Board must be in Loader mode: hdc shell "reboot loader" or RECOVERY+RESET & exit /b 1 )
set FAIL=0
echo [1/11] uboot
"%RKT%" wl 0x2000 uboot.img || set FAIL=1
echo [2/11] resource
"%RKT%" wl 0x7000 resource.img || set FAIL=1
echo [3/11] boot_linux
"%RKT%" wl 0xA000 boot_linux.img || set FAIL=1
echo [4/11] ramdisk
"%RKT%" wl 0x3A000 ramdisk.img || set FAIL=1
echo [5/11] system 2GB please wait
"%RKT%" wl 0x3C000 system.img || set FAIL=1
echo [6/11] vendor
"%RKT%" wl 0x43C000 vendor.img || set FAIL=1
echo [7/11] sys_prod
"%RKT%" wl 0x63C000 sys_prod.img || set FAIL=1
echo [8/11] chip_prod
"%RKT%" wl 0x655000 chip_prod.img || set FAIL=1
echo [9/11] updater
"%RKT%" wl 0x66E000 updater.img || set FAIL=1
echo [10/11] chip_ckm
"%RKT%" wl 0x69E000 chip_ckm.img || set FAIL=1
echo [11/11] userdata 1.4GB please wait
"%RKT%" wl 0x1308000 userdata.img || set FAIL=1
if %FAIL%==1 (
  echo FLASH_RESULT: FAILED - do NOT reboot, check output above
  exit /b 1
)
echo FLASH_RESULT: ALL_OK - resetting device
"%RKT%" rd
endlocal
