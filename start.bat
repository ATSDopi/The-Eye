@echo off
title The Eye - OSINT Toolkit
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8

REM direct passthrough: start.bat scan zuck --top 500
if not "%~1"=="" (
    python -m theeye %*
    goto :eof
)

:menu
cls
echo  ==================================================
echo    THE EYE - free OSINT toolkit
echo  ==================================================
echo.
echo    [1] Username scan   (6400+ sites, fp-verified)
echo    [2] Email intel     (gravatar, breaches, proton, intelx...)
echo    [3] Breach report   (merged leak timeline)
echo    [4] Domain intel    (dns, rdap, subdomains, ransomware...)
echo    [5] IP intel        (ports, CVEs, ASN, geo)
echo    [6] Phone intel     (parse + leaks)
echo    [7] Address intel   (geocoding OSM + BAN)
echo    [8] Crypto intel    (btc/eth/ltc/doge/sol/xmr)
echo    [9] DOSSIER         (TOTAL RESEARCH: cross everything)
echo    [d] Doxx report     (structured investigation report)
echo    [h] History         (past scans)
echo    [b] Site database   (stats / tags)
echo    [s] Site selfcheck  (flag FP-prone sites)
echo    [u] Update database (refresh site lists)
echo    [0] Quit
echo.
set /p CHOICE="  > "

if "%CHOICE%"=="1" goto scan
if "%CHOICE%"=="2" goto email
if "%CHOICE%"=="3" goto breach
if "%CHOICE%"=="4" goto domain
if "%CHOICE%"=="5" goto ip
if "%CHOICE%"=="6" goto phone
if "%CHOICE%"=="7" goto address
if "%CHOICE%"=="8" goto crypto
if "%CHOICE%"=="9" goto dossier
if /i "%CHOICE%"=="d" goto doxx
if /i "%CHOICE%"=="h" goto history
if /i "%CHOICE%"=="b" goto sites
if /i "%CHOICE%"=="s" goto selfcheck
if /i "%CHOICE%"=="u" goto update
if "%CHOICE%"=="0" goto :eof
goto menu

:scan
echo.
set /p U="  username: "
if "%U%"=="" goto menu
set /p TOP="  limit to top N sites [empty = all 5800+]: "
set /p NSFW="  include NSFW sites? [y/N]: "
set /p VARIANTS="  try variants (sep/common/full) [empty = no]: "
set ARGS=scan "%U%" --html
if not "%TOP%"=="" set ARGS=%ARGS% --top %TOP%
if /i "%NSFW%"=="y" set ARGS=%ARGS% --nsfw
if not "%VARIANTS%"=="" set ARGS=%ARGS% --variants %VARIANTS%
echo.
python -m theeye %ARGS%
echo.
pause
goto menu

:email
echo.
set /p E="  email address: "
if "%E%"=="" goto menu
python -m theeye email "%E%"
echo.
pause
goto menu

:breach
echo.
set /p B="  email address: "
if "%B%"=="" goto menu
python -m theeye breach "%B%" --html
echo.
pause
goto menu

:selfcheck
echo.
set /p N="  probe top N sites [empty = all 5800+, slow]: "
set SC=selfcheck
if not "%N%"=="" set SC=%SC% --top %N%
python -m theeye %SC%
echo.
pause
goto menu

:ip
echo.
set /p I="  ip address: "
if "%I%"=="" goto menu
python -m theeye ip "%I%"
echo.
pause
goto menu

:phone
echo.
set /p P="  phone (+33...): "
if "%P%"=="" goto menu
python -m theeye phone "%P%"
echo.
pause
goto menu

:address
echo.
set /p A="  postal address: "
if "%A%"=="" goto menu
python -m theeye address "%A%"
echo.
pause
goto menu

:crypto
echo.
set /p C="  crypto address (btc/eth/ltc/doge/sol/xmr): "
if "%C%"=="" goto menu
python -m theeye crypto "%C%"
echo.
pause
goto menu

:dossier
echo.
echo    leave empty = interactive mode (asks every field one by one)
echo    or give one target: email / domain / ip / phone / crypto / username
echo.
set /p T="  target [empty = interactive]: "
if "%T%"=="" (
    python -m theeye dossier --html
) else (
    python -m theeye dossier "%T%" --html
)
echo.
pause
goto menu

:doxx
echo.
echo    report creator: answer what you know, empty = skipped
echo    presets: full / identity / digital / network / minimal
echo.
set /p PRE="  preset [full]: "
if "%PRE%"=="" set PRE=full
python -m theeye doxx --preset %PRE% --html
echo.
pause
goto menu

:domain
echo.
set /p D="  domain (example.com): "
if "%D%"=="" goto menu
python -m theeye domain "%D%"
echo.
pause
goto menu

:history
python -m theeye history
echo.
pause
goto menu

:sites
python -m theeye sites --stats
echo.
set /p T="  list all tags? [y/N]: "
if /i "%T%"=="y" python -m theeye sites --tags
echo.
pause
goto menu

:update
python -m theeye update
echo.
pause
goto menu
