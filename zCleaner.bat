@echo off
title zCleaner
color 4f
cls

fltmc >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERREUR] Lancez ce script en ADMINISTRATEUR !
    pause
    exit
)

:MENU
cls
echo  =====================================================================
echo   /!\ V1.3 - No Reboot /!\
echo  =====================================================================
echo.
echo  CE SCRIPT VA :
echo   1. Fermer brutalement tous les navigateurs, jeux et l'Explorateur.
echo   2. SUPPRIMER DEFINITIVEMENT :
echo      - Historiques Web, Downloads, Caches (GPU, Discord, CrashDumps)
echo      - Miniatures (Thumbcache), Historique PowerShell, Notifications
echo      - Historique Windows Defender et Cache Cryptographique
echo   3. ECRASEMENT TOTAL : Fichier HOSTS, Registre BAM/ShimCache.
echo   4. VIDER le Presse-Papier.
echo   5. Relancer l'Explorateur Windows a la fin (Pas de redemarrage).
echo.
echo  [1] EXECUTER LE NETTOYAGE TOTAL
echo  [2] ANNULER
echo.
set /p "choix=Votre choix : "
if "%choix%"=="1" goto KILL_PHASE
if "%choix%"=="2" exit
goto MENU

:KILL_PHASE
cls
echo [PHASE 1/6] ARRET DES PROCESSUS...

taskkill /F /IM chrome.exe >nul 2>&1
taskkill /F /IM firefox.exe >nul 2>&1
taskkill /F /IM opera.exe >nul 2>&1
taskkill /F /IM msedge.exe >nul 2>&1
taskkill /F /IM brave.exe >nul 2>&1
taskkill /F /IM discord.exe >nul 2>&1
taskkill /F /IM steam.exe >nul 2>&1
taskkill /F /IM "battle.net.exe" >nul 2>&1

taskkill /F /IM explorer.exe >nul 2>&1
taskkill /F /IM SearchUI.exe >nul 2>&1
taskkill /F /IM SmartScreen.exe >nul 2>&1
taskkill /F /IM "Device Manager.exe" >nul 2>&1

net stop Winmgmt /y >nul 2>&1
net stop SysMain /y >nul 2>&1
net stop EventLog /y >nul 2>&1
net stop DiagTrack /y >nul 2>&1
net stop PcaSvc /y >nul 2>&1
net stop dps /y >nul 2>&1
net stop bam /y >nul 2>&1
net stop "WSearch" /y >nul 2>&1

echo.
echo [PHASE 2/6] DESTRUCTION DES DONNEES...

echo [DEL] Cache Visuel et Historiques Systemes...
del /F /Q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db" >nul 2>&1
del /F /Q "%LOCALAPPDATA%\Microsoft\Windows\Explorer\iconcache_*.db" >nul 2>&1
del /F /Q "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" >nul 2>&1
rd /s /q "C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service" >nul 2>&1
rd /s /q "%LOCALAPPDATA%\Microsoft\Windows\Notifications" >nul 2>&1
rd /s /q "%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\Content" >nul 2>&1
rd /s /q "%USERPROFILE%\AppData\LocalLow\Microsoft\CryptnetUrlCache\MetaData" >nul 2>&1
echo off | clip

echo [DEL] Rapports d'erreurs et RAC...
rd /s /q "C:\ProgramData\Microsoft\RAC" >nul 2>&1
rd /s /q "C:\ProgramData\Microsoft\RAC\PublishedData" >nul 2>&1
rd /s /q "C:\ProgramData\Microsoft\RAC\StateData" >nul 2>&1
rd /s /q "%LOCALAPPDATA%\CrashDumps" >nul 2>&1
rd /s /q "%LOCALAPPDATA%\Microsoft\Windows\WER" >nul 2>&1

echo [WIPE] Dossier Downloads...
del /F /S /Q "%USERPROFILE%\Downloads\*.*" >nul 2>&1
rd /s /q "%USERPROFILE%\Downloads" >nul 2>&1 & md "%USERPROFILE%\Downloads" >nul 2>&1

echo [DEL] Fichiers Recents et Recherche...
del /F /Q "%APPDATA%\Microsoft\Windows\Recent\*.*" >nul 2>&1
del /F /Q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*.*" >nul 2>&1
del /F /Q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*.*" >nul 2>&1
del /F /S /Q "C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb" >nul 2>&1
rd /s /q "C:\ProgramData\Microsoft\Search\Data\Applications\Windows" >nul 2>&1

echo [WIPE] Navigateurs Web...
rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data" >nul 2>&1
rd /s /q "%APPDATA%\Mozilla\Firefox\Profiles" >nul 2>&1
rd /s /q "%LOCALAPPDATA%\Mozilla\Firefox\Profiles" >nul 2>&1
rd /s /q "%LOCALAPPDATA%\Microsoft\Edge\User Data" >nul 2>&1
rd /s /q "%APPDATA%\Opera Software\Opera Stable" >nul 2>&1
rd /s /q "%APPDATA%\Opera Software\Opera GX Stable" >nul 2>&1

echo [WIPE] Cache Discord...
rd /s /q "%APPDATA%\Discord\Cache" >nul 2>&1
rd /s /q "%APPDATA%\Discord\Code Cache" >nul 2>&1
rd /s /q "%APPDATA%\Discord\GPUCache" >nul 2>&1

rd /s /q "%TEMP%" >nul 2>&1 & md "%TEMP%" >nul 2>&1
rd /s /q "C:\Windows\Temp" >nul 2>&1 & md "C:\Windows\Temp" >nul 2>&1
rd /s /q %systemdrive%\$Recycle.Bin >nul 2>&1
del /F /Q "C:\Windows\Prefetch\*.pf" >nul 2>&1
del /F /Q "C:\Windows\Prefetch\*.db" >nul 2>&1

del /F /Q "%LOCALAPPDATA%\D3DSCache\*.*" >nul 2>&1
del /F /Q "%LOCALAPPDATA%\NVIDIA\GLCache\*.*" >nul 2>&1
del /F /Q "%LOCALAPPDATA%\AMD\DxCache\*.*" >nul 2>&1

echo.
echo [PHASE 3/6] NETTOYAGE REGISTRE...

reg delete "HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings" /va /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v AppCompatCache /f >nul 2>&1
reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" /v BamAppCompat /f >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /va /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /va /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /va /f >nul 2>&1

reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f >nul 2>&1
reg delete "HKCR\Local Settings\Software\Microsoft\Windows\Shell\MuiCache" /va /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\BagMRU" /f >nul 2>&1
reg delete "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU" /va /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f >nul 2>&1

echo.
echo [PHASE 4/6] RESEAU ET PERIPHERIQUES...

ipconfig /flushdns >nul 2>&1
attrib -r -s -h "C:\Windows\System32\drivers\etc\hosts" >nul 2>&1
del /F /Q "C:\Windows\System32\drivers\etc\hosts" >nul 2>&1
(echo 127.0.0.1 localhost) > "C:\Windows\System32\drivers\etc\hosts"

del /F /Q "C:\Windows\INF\setupapi.dev.log" >nul 2>&1
del /F /Q "C:\Windows\INF\setupapi.app.log" >nul 2>&1
pnputil /remove-device /class "USBDevice" /disconnected >nul 2>&1

powershell -Command "$p='HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'; if(Test-Path $p){try{$a=Get-Acl $p;$r=New-Object System.Security.AccessControl.RegistryAccessRule('Administrateurs','FullControl','Allow');$a.SetAccessRule($r);Set-Acl $p $a;Remove-Item $p -Recurse -Force;New-Item -Path $p -Force|Out-Null;Write-Host '[OK] USBSTOR Detruit'}catch{}}" >nul 2>&1

echo.
echo [PHASE 5/6] PURGE DES LOGS...
wevtutil cl Security >nul 2>&1
wevtutil cl System >nul 2>&1
wevtutil cl Application >nul 2>&1
del /F /Q "C:\Windows\System32\winevt\Logs\*.evtx" >nul 2>&1
rd /s /q "C:\Windows\System32\LogFiles\WMI\RtBackup" >nul 2>&1

echo.
echo [PHASE 6/6] RELANCE DE L'INTERFACE...

net start EventLog >nul 2>&1
net start Winmgmt >nul 2>&1
start explorer.exe

echo.
echo  =============================================================
echo   CleanUp TERMINE !
echo  =============================================================
echo   Note : RAM et Kernel Cache persistent (Pas de reboot).
echo   Mais Fichiers, Registre et Historiques sont detruits.
echo.
echo  Appuyez sur une touche pour supprimer ce script et quitter.
pause >nul

(goto) 2>nul & del "%~f0"