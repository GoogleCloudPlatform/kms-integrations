:: Simple signing script for the KMS oss-tools Windows artifacts

echo "Starting signing job:"

:: The parent job's output artifacts get copied to KOKORO_GFILE_DIR.
:: go/kokoro-grouping#artifacts-transfer
cd "%KOKORO_GFILE_DIR%\outputs"

:: Display dir contents for logging.
dir /s

:: Create the standard output results directory.
:: Copy PKCS#11 and CNG artifacts to the output dir to sign them in place.
:: Note: rename the two files in the process, because input constructions is
:: not guaranteed in chained Kokoro jobs.
:: See warning at the bottom of go/kokoro-grouping#artifacts-transfer.
set RESULTS_DIR=%KOKORO_ARTIFACTS_DIR%\results
mkdir "%RESULTS_DIR%"
mkdir "%RESULTS_DIR%\signed"
copy kmsp11.h "%RESULTS_DIR%\signed\kmsp11.h"
copy LICENSE "%RESULTS_DIR%\signed\LICENSE"
copy kmsp11_unsigned.dll "%RESULTS_DIR%\signed\kmsp11_google_signed.dll"
copy kmscng_unsigned.msi "%RESULTS_DIR%\signed\kmscng_google_signed.msi"
cd "%RESULTS_DIR%\signed"

:: Attempt the signing for PKCS#11
ksigntool.exe sign GOOGLE_EXTERNAL /v /debug /t http://timestamp.digicert.com "kmsp11_google_signed.dll"

:: Attempt the signing for CNG
ksigntool.exe sign GOOGLE_EXTERNAL /v /debug /t http://timestamp.digicert.com "kmscng_google_signed.msi"

echo "All artifacts signed successfully!"
