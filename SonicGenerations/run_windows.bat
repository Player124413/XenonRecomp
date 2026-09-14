@echo off
rem Sonic Generations recompilation script (Windows).
rem
rem Place your decrypted "default.xex" next to this script, then run it.
rem Output: generated C++ sources in .\ppc\

setlocal enabledelayedexpansion
cd /d "%~dp0"

set "RECOMP="
set "ANALYSE="
for %%p in ("..\build\XenonRecomp\XenonRecomp.exe" "..\build\XenonRecomp\Release\XenonRecomp.exe" "..\build\Release\XenonRecomp.exe") do (
    if exist %%p set "RECOMP=%%~p"
)
for %%p in ("..\build\XenonAnalyse\XenonAnalyse.exe" "..\build\XenonAnalyse\Release\XenonAnalyse.exe" "..\build\Release\XenonAnalyse.exe") do (
    if exist %%p set "ANALYSE=%%~p"
)

if not defined RECOMP (
    echo ERROR: XenonRecomp.exe not found. Build the project first:
    echo    cmake -S .. -B ..\build -DCMAKE_BUILD_TYPE=Release
    echo    cmake --build ..\build --config Release
    echo ^(or open the repository in Visual Studio and build the XenonRecomp target^)
    exit /b 1
)
if not defined ANALYSE (
    echo ERROR: XenonAnalyse.exe not found. Build the project first.
    exit /b 1
)

if not exist default.xex (
    echo ERROR: Place your decrypted Sonic Generations 'default.xex' into this folder first.
    echo        See README.md in this folder for details ^(the file must be DECRYPTED^).
    exit /b 1
)

echo.
echo === Step 1/2: Detecting jump tables ^(XenonAnalyse^) ===
"%ANALYSE%" default.xex switch_tables.toml
if errorlevel 1 exit /b 1

echo.
echo === Step 2/2: Recompiling to C++ ^(XenonRecomp^) ===
"%RECOMP%" config.toml "..\XenonUtils\ppc_context.h"
if errorlevel 1 exit /b 1

echo.
echo Done! The generated C++ sources are in SonicGenerations\ppc\
echo See README.md for what to do next ^(you need a runtime to actually play^).
