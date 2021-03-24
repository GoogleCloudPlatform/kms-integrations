@echo on

:: Code under repo is checked out to %KOKORO_ARTIFACTS_DIR%\git.
:: The final directory name in this path is determined by the scm name specified
:: in the job configuration.
set PROJECT_ROOT=%KOKORO_ARTIFACTS_DIR%\git\oss-tools
cd "%PROJECT_ROOT%"

set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
mkdir "%RESULTS_DIR%"

choco install -y bazel --version 4.0.0

:: Configure user.bazelrc with remote build caching options
copy .kokoro\remote_cache.bazelrc user.bazelrc
echo build --remote_default_exec_properties=cache-silo-key=windows >> user.bazelrc

:: https://docs.bazel.build/versions/master/windows.html#build-c-with-msvc
set BAZEL_VC=C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\

:: Force msys2 environment instead of Cygwin
set PATH=C:\tools\msys64\usr\bin;%PATH%
set BAZEL_SH=C:\tools\msys64\usr\bin\bash.exe

:: Use our scratch drive for temp space
mkdir T:\buildtmp
set TMP=T:\buildtmp

:: Ensure Bazel version information is included in the build log
bazel version

bazel test -c opt %BAZEL_EXTRA_ARGS% ... :release_tests --keep_going
set RV=%ERRORLEVEL%

if exist "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" ^
    "%RESULTS_DIR%\kmsp11.dll"

python "%PROJECT_ROOT%\.kokoro\copy_test_outputs.py" ^
    "%PROJECT_ROOT%\bazel-testlogs" "%RESULTS_DIR%\testlogs"

exit %RV%
