:: Simple Signing Script for the KMS oss-tools Windows artifacts

echo "We start here:"
dir

:: The parent job's output artifacts should have been copied to KOKORO_GFILE_DIR.
:: go/kokoro-grouping#artifacts-transfer
cd "%KOKORO_GFILE_DIR%"

:: Display dir contents for logging
dir /s

:: Create the standard output artifacts directory.
:: Copy PKCS#11 and CNG artifacts to the output dir to sign them in place.
mkdir "%KOKORO_ARTIFACTS_DIR%\artifacts"
copy kmsp11.dll "%KOKORO_ARTIFACTS_DIR%\artifacts"
copy kmscng.msi "%KOKORO_ARTIFACTS_DIR%\artifacts"
cd "%KOKORO_ARTIFACTS_DIR%\artifacts"

:: Attempt the signing for PKCS#11
ksigntool.exe sign GOOGLE_EXTERNAL /v /debug /t http://timestamp.digicert.com "kmsp11.dll"

:: Attempt the signing for CNG
ksigntool.exe sign GOOGLE_EXTERNAL /v /debug /t http://timestamp.digicert.com "kmscng.msi"

:: Display dir contents for logging
dir /s

:: Verify checks for logging
ksigntool.exe verify /pa /all /debug "kmsp11.dll"
ksigntool.exe verify /pa /all /debug "kmscng.msi"

echo "All artifacts signed successfully!"

