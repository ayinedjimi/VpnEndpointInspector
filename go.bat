@echo off
echo Compilation de VpnEndpointInspector...
cl.exe /EHsc /W4 /std:c++17 /Fe:VpnEndpointInspector.exe VpnEndpointInspector.cpp /link rasapi32.lib advapi32.lib comctl32.lib user32.lib gdi32.lib
if %ERRORLEVEL% EQU 0 (
    echo Compilation reussie!
    echo Executable: VpnEndpointInspector.exe
) else (
    echo Erreur de compilation.
)
pause
