:: Simple Signing Script for the KMS oss-tools Windows artifacts

echo "We start here:"
dir

:: The parent job's output artifacts should have been copied to KOKORO_GFILE_DIR.
:: go/kokoro-grouping#artifacts-transfer
cd "%KOKORO_GFILE_DIR%"

:: Display dir contents for logging
dir /s

:: Create the standard output results directory.
:: Copy PKCS#11 and CNG artifacts to the output dir to sign them in place.
set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
mkdir "%RESULTS_DIR%"
copy kmsp11.dll "%RESULTS_DIR%"
copy kmscng.msi "%RESULTS_DIR%"
cd "%RESULTS_DIR%"

:: Attempt the signing for PKCS#11
ksigntool.exe sign GOOGLE_EXTERNAL /v /debug /t http://timestamp.digicert.com "kmsp11.dll"

:: Attempt the signing for CNG
ksigntool.exe sign GOOGLE_EXTERNAL /v /debug /t http://timestamp.digicert.com "kmscng.msi"

echo "All artifacts signed successfully!"

