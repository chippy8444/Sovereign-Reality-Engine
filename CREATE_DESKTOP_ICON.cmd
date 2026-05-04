@echo off
setlocal
set TARGET=%~dp0START_RESOLUTION_AI.cmd
set SHORTCUT=%USERPROFILE%\Desktop\Resolution AI.lnk
powershell -NoProfile -ExecutionPolicy Bypass -Command "$W=New-Object -ComObject WScript.Shell; $S=$W.CreateShortcut('%SHORTCUT%'); $S.TargetPath='%TARGET%'; $S.WorkingDirectory='%~dp0'; $S.IconLocation='%SystemRoot%\System32\shell32.dll,44'; $S.Save()"
echo Created desktop icon: %SHORTCUT%
pause
