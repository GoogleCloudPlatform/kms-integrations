@echo on

:: Code under repo is checked out to %KOKORO_ARTIFACTS_DIR%\git.
:: The final directory name in this path is determined by the scm name specified
:: in the job configuration.
set PROJECT_ROOT=%KOKORO_ARTIFACTS_DIR%\git\oss-tools
cd "%PROJECT_ROOT%"

set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
mkdir "%RESULTS_DIR%"

:: Add the latest version of Bazel to the PATH
choco install bazel --version 3.0.0 -y --no-progress || exit /b

:: https://docs.bazel.build/versions/master/windows.html#build-c-with-msvc
set BAZEL_VC=C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\

:: Force msys2 environment instead of Cygwin
set PATH=C:\tools\msys64\usr\bin;%PATH%
set BAZEL_SH=C:\tools\msys64\usr\bin\bash.exe

bazel test ...
set RV=%ERRORLEVEL%

C:\Python37\python.exe "%PROJECT_ROOT%\.kokoro\copy_test_outputs.py" ^
    "%PROJECT_ROOT%\bazel-testlogs" "%RESULTS_DIR%\testlogs"

exit %RV%
