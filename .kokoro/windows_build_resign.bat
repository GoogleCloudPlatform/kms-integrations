:: Re-sign Windows artifacts with our KMS-stored OSS key.

setlocal enabledelayedexpansion
echo "Starting build re-signing job:"

:: The parent job's output artifacts get copied to KOKORO_GFILE_DIR.
:: go/kokoro-grouping#artifacts-transfer
cd "%KOKORO_GFILE_DIR%"

:: Display dir contents for logging.
dir /s

:: Parse kmsp11 version from kmsp11/version.h (Format: {major, minor})
for /f "usebackq tokens=5,6 delims={,; " %%a in (`findstr "kLibraryVersion =" kmsp11\version.h`) do (
    set P11_MAJOR=%%a
    set P11_MINOR=%%b
)
set P11_VERSION=%P11_MAJOR%.%P11_MINOR%

:: Parse kmscng version from kmscng/version.h (Format: kLibraryVersionX = Y;)
for /f "usebackq tokens=5 delims=; " %%a in (`findstr "kLibraryVersionMajor =" kmscng\version.h`) do set CNG_MAJOR=%%a
for /f "usebackq tokens=5 delims=; " %%a in (`findstr "kLibraryVersionMinor =" kmscng\version.h`) do set CNG_MINOR=%%a
set CNG_VERSION=%CNG_MAJOR%.%CNG_MINOR%

:: Create the standard output results directory.
:: Copy PKCS#11 and CNG artifacts to the output dir to sign them in place.
set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
set RESULTS_DIR_P11=%RESULTS_DIR%\libkmsp11-%P11_VERSION%-windows-amd64
set RESULTS_DIR_CNG=%RESULTS_DIR%\kmscng-%CNG_VERSION%-windows-amd64
mkdir "%RESULTS_DIR_P11%"
mkdir "%RESULTS_DIR_CNG%"
copy kmsp11_google_signed.dll "%RESULTS_DIR_P11%\kmsp11.dll"
copy kmscng_google_signed.msi "%RESULTS_DIR_CNG%\kmscng.msi"

echo "Now re-sign both artifacts using our buildsigner tool:"

:: Code under repo is checked out to %KOKORO_ARTIFACTS_DIR%\git.
:: The final directory name in this path is determined by the scm name specified
:: in the job configuration.
set PROJECT_ROOT=%KOKORO_ARTIFACTS_DIR%\git\oss-tools
cd "%PROJECT_ROOT%"

:: Copy License (and p11 header) for release
copy .\LICENSE %RESULTS_DIR_P11%\
copy .\kmsp11\kmsp11.h %RESULTS_DIR_P11%\
copy .\LICENSE %RESULTS_DIR_CNG%\

:: Get Bazelisk
msiexec /i %KOKORO_GFILE_DIR%\go1.22.0.windows-amd64.msi /qn
set GOROOT=C:\Program Files\go
set GOPATH=%KOKORO_ARTIFACTS_DIR%\gopath
go install github.com/bazelbuild/bazelisk@v1.25.0
set PATH=%GOPATH%\bin;%PATH%

echo Updating gcloud components..
call gcloud components update --quiet

:: Pull in the service account key
set GOOGLE_APPLICATION_CREDENTIALS=%KOKORO_ARTIFACTS_DIR%\oss-tools-ci-key.json
call gcloud secrets versions access latest --secret=oss-tools-ci-key --project=oss-tools-build --out-file=%GOOGLE_APPLICATION_CREDENTIALS%

:: Create and configure user.bazelrc
echo build --google_default_credentials=true > user.bazelrc

:: Force msys2 environment instead of Cygwin
set PATH=C:\msys64\usr\bin;%PATH%
set BAZEL_SH=C:\msys64\usr\bin\bash.exe
set BAZEL_ARGS=-c opt --keep_going --enable_runfiles %BAZEL_EXTRA_ARGS%
:: https://bazel.build/configure/windows#long-path-issues
set BAZEL_STARTUP_ARGS=--output_user_root c:\bzltmp

:: Sign PKCS#11 DLL
bazelisk %BAZEL_STARTUP_ARGS% run %BAZEL_ARGS% //kmsp11/tools/buildsigner -- ^
  -signing_key=%BUILD_SIGNING_KEY% ^
  < "%RESULTS_DIR_P11%\kmsp11.dll" ^
  > "%RESULTS_DIR_P11%\kmsp11.dll.sig"

:: Ensure the previous resigning step succeeded before attempting AR upload
if !ERRORLEVEL! neq 0 (
    echo "[ERROR] P11 resigning process failed. Skipping Artifact Registry upload."
    exit /b !ERRORLEVEL!
)

:: Sign CNG MSI
bazelisk %BAZEL_STARTUP_ARGS% run %BAZEL_ARGS% //kmsp11/tools/buildsigner -- ^
  -signing_key=%BUILD_SIGNING_KEY% ^
  < "%RESULTS_DIR_CNG%\kmscng.msi" ^
  > "%RESULTS_DIR_CNG%\kmscng.msi.sig"

:: Ensure the previous resigning step succeeded before attempting AR upload
if !ERRORLEVEL! neq 0 (
    echo "[ERROR] CNG resigning process failed. Skipping Artifact Registry upload."
    exit /b !ERRORLEVEL!
)

:: Zip files for release
cd %RESULTS_DIR%
:: Display dir contents for logging
dir /s
zip -r libkmsp11-%P11_VERSION%-windows-amd64.zip libkmsp11-%P11_VERSION%-windows-amd64
copy libkmsp11-%P11_VERSION%-windows-amd64.zip %RESULTS_DIR_P11%\
zip -r kmscng-%CNG_VERSION%-windows-amd64.zip kmscng-%CNG_VERSION%-windows-amd64
copy kmscng-%CNG_VERSION%-windows-amd64.zip %RESULTS_DIR_CNG%\

:: Upload kmsp11 Windows artifacts
call gcloud components update --quiet
call gcloud artifacts generic upload ^
    --project=oss-exit-gate-prod ^
    --repository=kms-integrations--githubreleases ^
    --location=us ^
    --package="libkmsp11-windows-amd64" ^
    --version=%P11_VERSION% ^
    --source="%RESULTS_DIR_P11%\libkmsp11-%P11_VERSION%-windows-amd64.zip"
if !ERRORLEVEL! neq 0 exit /b !ERRORLEVEL!

:: Upload kmscng Windows artifacts
call gcloud artifacts generic upload ^
    --project=oss-exit-gate-prod ^
    --repository=kms-integrations--githubreleases ^
    --location=us ^
    --package="kmscng-windows-amd64" ^
    --version=%CNG_VERSION% ^
    --source="%RESULTS_DIR_CNG%\kmscng-%CNG_VERSION%-windows-amd64.zip"
if !ERRORLEVEL! neq 0 exit /b !ERRORLEVEL!

exit /b !ERRORLEVEL!
