# MIT License
#
# Copyright (c) 2026 DeJavaEx
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$build = Join-Path $root "build"
$javaOutput = Join-Path $build "java-engine"
$javaArchive = Join-Path $build "java-engine.jar"
$decompilerArchive = Join-Path $build "cfr-0.152.jar"
$nativeOutput = Join-Path $build "native"
$publishOutput = Join-Path $build "publish"
$javaSource = Join-Path $root "src\engine\java\src\main\java"
$nativeSource = Join-Path $root "src\engine\native\src"
New-Item -ItemType Directory -Force -Path $javaOutput, $nativeOutput | Out-Null

if (-not (Test-Path $decompilerArchive)) {
    $curl = Get-Command curl.exe -ErrorAction SilentlyContinue
    if (-not $curl) { throw "curl.exe is required to download CFR 0.152 for Java source decompilation." }
    & $curl.Source --fail --location --silent --show-error --output $decompilerArchive "https://repo.maven.apache.org/maven2/org/benf/cfr/0.152/cfr-0.152.jar"
    if ($LASTEXITCODE -ne 0) { throw "CFR 0.152 download failed." }
}

$jdkHome = $env:JAVA_HOME
$javaInstallRoot = Join-Path $env:ProgramFiles "Java"
if (-not $jdkHome -and (Test-Path (Join-Path $javaInstallRoot "latest\bin\javac.exe"))) {
    $jdkHome = Join-Path $javaInstallRoot "latest"
}
if (-not $jdkHome -and (Test-Path (Join-Path $javaInstallRoot "jdk-27\bin\javac.exe"))) {
    $jdkHome = Join-Path $javaInstallRoot "jdk-27"
}
$javacPath = if ($jdkHome) { Join-Path $jdkHome "bin\javac.exe" } else { (Get-Command javac -ErrorAction SilentlyContinue).Source }
$jarPath = if ($jdkHome) { Join-Path $jdkHome "bin\jar.exe" } else { (Get-Command jar -ErrorAction SilentlyContinue).Source }
if (-not $javacPath -or -not (Test-Path $jarPath)) {
    throw "A JDK is required to compile and package the Java bytecode engine."
}
$javaFiles = Get-ChildItem $javaSource -Filter "*.java" -Recurse | Select-Object -ExpandProperty FullName
& $javacPath -encoding UTF-8 --release 11 -d $javaOutput $javaFiles
if ($LASTEXITCODE -ne 0) { throw "Java engine compilation failed." }
& $jarPath --create --file $javaArchive --main-class dejava.StaticAnalyzer -C $javaOutput .
if ($LASTEXITCODE -ne 0) { throw "Java engine packaging failed." }
Write-Host "Java analysis engine compiled and packaged."
Write-Host "CFR Java source decompiler is ready."

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { throw "Visual Studio Installer (vswhere) was not found. Install the C++ desktop development workload." }
$vsInstall = & $vswhere -latest -products "*" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw "MSVC C++ tools were not found. Install the Visual Studio C++ desktop development workload." }
$devCommand = Join-Path $vsInstall "Common7\Tools\VsDevCmd.bat"
$nativeFiles = (Get-ChildItem $nativeSource -Filter "*.cpp" -Recurse | ForEach-Object { '"' + $_.FullName + '"' }) -join ' '
$nativeCommand = 'call "' + $devCommand + '" -no_logo -arch=x64 && cl /nologo /std:c++17 /EHsc /I"' + (Join-Path $root "src\engine\native\include") + '" ' + $nativeFiles + ' /Fe:dejavaex-engine.exe /link bcrypt.lib'
Push-Location $nativeOutput
try {
    & $env:ComSpec /d /c $nativeCommand
    if ($LASTEXITCODE -ne 0) { throw "C++ static-analysis engine compilation failed." }
} finally {
    Pop-Location
}
Write-Host "C++ static-analysis engine built."

if (Test-Path $publishOutput) {
    $publishedExecutable = Join-Path $publishOutput "DeJavaEx.exe"
    $runningBuild = Get-CimInstance Win32_Process -Filter "Name = 'DeJavaEx.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.ExecutablePath -eq $publishedExecutable }
    if ($runningBuild) {
        $publishOutput = Join-Path $build ("publish-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
        Write-Warning "DeJavaEx is currently running; publishing the update to $publishOutput instead of replacing the locked executable."
    }
}

dotnet publish (Join-Path $root "src\desktop\DeJavaEx.UI\DeJavaEx.UI.csproj") -c Release -r win-x64 --self-contained true `
    -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true -o $publishOutput
if ($LASTEXITCODE -ne 0) { throw "DeJavaEx WPF publishing failed." }
Write-Host "Published single-file application: $publishOutput\DeJavaEx.exe"