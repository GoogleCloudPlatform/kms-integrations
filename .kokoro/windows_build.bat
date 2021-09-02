:: Copyright 2021 Google LLC
::
:: Licensed under the Apache License, Version 2.0 (the "License");
:: you may not use this file except in compliance with the License.
:: You may obtain a copy of the License at
::
::      http://www.apache.org/licenses/LICENSE-2.0
::
:: Unless required by applicable law or agreed to in writing, software
:: distributed under the License is distributed on an "AS IS" BASIS,
:: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
:: See the License for the specific language governing permissions and
:: limitations under the License.

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

set BAZEL_ARGS=-c opt --keep_going %BAZEL_EXTRA_ARGS%

bazel test %BAZEL_ARGS% ... :release_tests
set RV=%ERRORLEVEL%

bazel run %BAZEL_ARGS% //kmsp11/tools/buildsigner -- ^
  -signing_key=%BUILD_SIGNING_KEY% ^
  < "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" ^
  > "%RESULTS_DIR%\kmsp11.dll.sig"
set SIGN_RV=%ERRORLEVEL%

if exist "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" copy ^
    "%PROJECT_ROOT%\bazel-bin\kmsp11\main\libkmsp11.so" ^
    "%RESULTS_DIR%\kmsp11.dll"

copy "%PROJECT_ROOT%/LICENSE" "%RESULTS_DIR%"
copy "%PROJECT_ROOT%/NOTICE" "%RESULTS_DIR%"

python "%PROJECT_ROOT%\.kokoro\copy_test_outputs.py" ^
    "%PROJECT_ROOT%\bazel-testlogs" "%RESULTS_DIR%\testlogs"

if not %RV% == 0 exit %RV% else exit %SIGN_RV%
