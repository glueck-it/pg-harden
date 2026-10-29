#Requires -Version 5.1
<#
.SYNOPSIS
  Admin-Selbsttest für pg-harden unter Windows: legt ein temporäres lokales Konto ohne Administratorrechte an,
  prüft die Lese- und Schreibseite (client --user, check/WindowsFacts, apply/rollback mit WindowsPin) gegen
  Junctions im Profil- und Datenverzeichnis dieses Kontos und räumt Konto, Profilschlüssel und Ordner am Ende ab.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\tests\windows-admin-test.ps1
#>
param(
  [string]$PhpExe = 'php.exe'
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  [Console]::Error.WriteLine('FEHLER: Dieses Skript muss in einer Administrator-PowerShell gestartet werden.')
  exit 2
}

$phpCmd = Get-Command $PhpExe -ErrorAction SilentlyContinue
if (-not $phpCmd) {
  [Console]::Error.WriteLine("FEHLER: PHP ($PhpExe) nicht im PATH gefunden. Bitte mit -PhpExe C:\Pfad\zu\php.exe aufrufen.")
  exit 2
}
$phpPath = $phpCmd.Source
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$entryPoint = Join-Path $repoRoot 'pg-harden.php'

$suffix = [guid]::NewGuid().ToString('N').Substring(0, 5)
$userName = "pgh$suffix"
$tempBase = (Get-Item $env:TEMP).FullName
$workRoot = Join-Path $tempBase "pgh-adm-$suffix"
$profileDir = Join-Path $workRoot 'Profile'
$dataDir = Join-Path $workRoot 'Data'
$adminDir = Join-Path $workRoot 'AdminOnly'
$journalDir = Join-Path $workRoot 'Journal'
$foreignDir = Join-Path $workRoot 'ForeignOut'
$regKeyPath = $null
$regKeyCreated = $false
$userSid = $null
$userCreated = $false
$links = New-Object System.Collections.Generic.List[string]
$failed = 0
# Der Arbeitsordner wird am Ende entfernt: er muss neu sein, ein gleichnamiger Ordner (Rest eines alten Laufs) bleibt unangetastet.
if (Test-Path -LiteralPath $workRoot) {
  [Console]::Error.WriteLine("FEHLER: $workRoot gibt es schon — abgebrochen, nichts geändert.")
  exit 2
}
if (Get-LocalUser -Name $userName -ErrorAction SilentlyContinue) {
  [Console]::Error.WriteLine("FEHLER: Konto $userName gibt es schon — abgebrochen, nichts geändert.")
  exit 2
}

function Check-Case([string]$Name, [string]$Want, [scriptblock]$Action) {
  try {
    $got = & $Action
  } catch {
    $got = 'Ausnahme: ' + $_.Exception.Message
  }
  if ($got -eq $Want) {
    Write-Host ("OK     " + $Name + ": " + $got)
  } else {
    $script:failed++
    Write-Host ("FEHLER " + $Name + ": " + $got + " (erwartet: " + $Want + ")") -ForegroundColor Red
  }
}

# client --user=<Testkonto> als JSON-Datei (-o); fehlt sie, wird die Ausgabe von pg-harden gezeigt statt das Skript abzubrechen.
function Invoke-ClientJson([string]$User) {
  # Windows PowerShell 5.1 macht mit "Stop" und 2>&1 schon aus der ersten stderr-Zeile einen Abbruch: hier nur sammeln.
  $ErrorActionPreference = 'Continue'
  $file = Join-Path ([IO.Path]::GetTempPath()) ('pgh-client-' + [guid]::NewGuid().ToString('N') + '.json')
  try {
    $raw = (& $script:phpPath $script:entryPoint client "--user=$User" -o $file 2>&1 | Out-String)
    if (Test-Path -LiteralPath $file) {
      try { return (Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json) } catch {}
    }
  } finally {
    Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
  }
  Write-Host "FEHLER client --user lieferte keinen JSON-Bericht:`n$raw" -ForegroundColor Red
  return [pscustomobject]@{ results = @() }
}

function New-Junction([string]$Link, [string]$Target) {
  cmd /c mklink /J "`"$Link`"" "`"$Target`"" >$null 2>&1
  if ($LASTEXITCODE -eq 0) {
    $script:links.Add($Link)
    return $true
  }
  return $false
}

function Remove-JunctionSafe([string]$Link) {
  if (Test-Path -LiteralPath $Link) {
    try { [IO.Directory]::Delete($Link) } catch { cmd /c rmdir "`"$Link`"" >$null 2>&1 }
  }
}

try {
  # 1. Lokales Standardkonto ohne Admin-Rechte anlegen
  $rawPass = 'PgH!' + [guid]::NewGuid().ToString('N').Substring(0, 12) + '9aA'
  $secPass = ConvertTo-SecureString $rawPass -AsPlainText -Force
  # Deaktiviert: das Konto meldet sich nie an, es braucht nur eine SID, die Besitzer und Berechtigter sein kann.
  New-LocalUser -Name $userName -Password $secPass -Description 'pg-harden temporäres Testkonto' -AccountNeverExpires -UserMayNotChangePassword -Disabled | Out-Null
  $userCreated = $true
  $userSid = (New-Object Security.Principal.NTAccount($userName)).Translate([Security.Principal.SecurityIdentifier]).Value
  Write-Host "--     Testkonto angelegt: $userName ($userSid)"

  # 2. Wegwerf-Verzeichnisse unter %TEMP% aufbauen
  New-Item -ItemType Directory -Path $profileDir, $dataDir, $adminDir | Out-Null
  New-Item -ItemType Directory -Path (Join-Path $profileDir 'AppData\Roaming\postgresql'), (Join-Path $profileDir 'Documents'), (Join-Path $profileDir 'Scripts') | Out-Null

  # Admin-Geheimnis außerhalb des Kontoprofils und Datenverzeichnisses
  Set-Content -LiteralPath (Join-Path $adminDir 'pgpass.conf') -Value "localhost:5432:*:postgres:adminSecret`n" -Encoding Ascii -NoNewline
  Set-Content -LiteralPath (Join-Path $adminDir 'postgresql.conf') -Value "# admin-only`n" -Encoding Ascii -NoNewline
  Set-Content -LiteralPath (Join-Path $adminDir 'deploy.ps1') -Value "PGPASSWORD=adminSecret`n" -Encoding Ascii -NoNewline
  icacls $adminDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" >$null

  # Dem Testkonto gehören sein Profil und das simulierte Datenverzeichnis (Vollzugriff dort, keine Admin-Rechte)
  icacls $profileDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*${userSid}:(OI)(CI)F" /T >$null
  icacls $dataDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*${userSid}:(OI)(CI)F" /T >$null

  # Profilverzeichnis für client --user=<Testkonto> in ProfileList eintragen
  $regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$userSid"
  if (Test-Path -LiteralPath $regKeyPath) {
    throw "ProfileList enthält schon einen Eintrag für $userSid — abgebrochen, nichts an fremden Einträgen geändert."
  }
  # Ohne -Force: ein inzwischen entstandener Schlüssel wirft einen Fehler, statt übernommen zu werden; gelöscht wird nur der eigene.
  New-Item -Path $regKeyPath | Out-Null
  $regKeyCreated = $true
  New-ItemProperty -LiteralPath $regKeyPath -Name 'ProfileImagePath' -Value $profileDir -PropertyType ExpandString -Force | Out-Null

  # Eigene Dateien im Profil des Testkontos
  $ownPgpass = Join-Path $profileDir 'AppData\Roaming\postgresql\pgpass.conf'
  Set-Content -LiteralPath $ownPgpass -Value "db.intern:5432:app:appuser:ownSecret`n" -Encoding Ascii -NoNewline
  # Absichtlich zu offene ACL auf der eigenen pgpass.conf (Jeder = S-1-1-0 darf lesen), damit pgpass_acl anschlägt
  icacls $ownPgpass /grant "*S-1-1-0:R" >$null
  Set-Content -LiteralPath (Join-Path $profileDir 'Scripts\deploy.ps1') -Value "PGPASSWORD=ownSecret`n" -Encoding Ascii -NoNewline

  # Junction im Profil auf das Admin-Verzeichnis. Angelegt vom Skript, nicht durch eine Anmeldung als Testkonto: eine Anmeldung
  # (Start-Process -Credential) lässt Windows ein eigenes Profil anlegen und den Eintrag in ProfileList umbiegen — dann prüfte
  # client --user ein anderes Profil. Dass ein Konto ohne Administratorrechte Junctions anlegen kann, belegt tests/windows-redirect.php.
  $juncInDocs = Join-Path $profileDir 'Documents\AdminLink'
  New-Junction $juncInDocs $adminDir | Out-Null
  Check-Case 'Junction im Profil des Standardkontos angelegt' 'ja' { if (Test-Path -LiteralPath $juncInDocs) { 'ja' } else { 'nein' } }
  Check-Case 'ProfileList zeigt auf das vorbereitete Profil' 'ja' {
    if ([string](Get-ItemProperty -LiteralPath $regKeyPath).ProfileImagePath -eq $profileDir) { 'ja' } else { 'nein: ' + (Get-ItemProperty -LiteralPath $regKeyPath).ProfileImagePath }
  }

  # 3. client --user=<Testkonto>: eigene Datei wird geprüft, Junction zum Admin-Ordner wird abgewiesen
  $clientReport = Invoke-ClientJson $userName
  $aclRes = $clientReport.results | Where-Object { $_.id -eq 'client.pgpass_acl' }
  $secRes = $clientReport.results | Where-Object { $_.id -eq 'client.secrets_in_files' }
  Check-Case 'client --user findet offene ACL der eigenen pgpass.conf (über Handle)' 'fail' { [string]$aclRes.status }
  Check-Case 'client --user findet eigenes Skript, liest nichts hinter der Junction' 'nur eigenes Skript' {
    $objs = @($secRes.findings | ForEach-Object { [string]$_.object })
    $hasOwn = ($objs | Where-Object { $_ -like '*\Scripts\deploy.ps1*' }).Count -gt 0
    $hasAdmin = ($objs | Where-Object { $_ -like '*AdminLink*' -or $_ -like '*AdminOnly*' }).Count -gt 0
    if ($hasOwn -and -not $hasAdmin) { 'nur eigenes Skript' } else { 'Funde: ' + ($objs -join ', ') }
  }

  # Jetzt ersetzt das Standardkonto seinen postgresql-Ordner im Profil durch eine Junction auf AdminOnly
  Remove-Item -LiteralPath $ownPgpass -Force
  Remove-Item -LiteralPath (Join-Path $profileDir 'AppData\Roaming\postgresql') -Force
  New-Junction (Join-Path $profileDir 'AppData\Roaming\postgresql') $adminDir | Out-Null

  $clientReport2 = Invoke-ClientJson $userName
  $aclRes2 = $clientReport2.results | Where-Object { $_.id -eq 'client.pgpass_acl' }
  Check-Case 'client --user weist pgpass.conf hinter Junction bei ACL-Prüfung ab' 'nicht geprüft' {
    # Im Bericht stehen nicht geprüfte Stellen als notes mit "nicht geprüft: …" und incomplete = true (es gibt kein Feld unchecked).
    $unch = @($aclRes2.notes | Where-Object { $_ -like 'nicht geprüft:*Junction*' })
    if (@($aclRes2.findings).Count -eq 0 -and $aclRes2.incomplete -eq $true -and $unch.Count -gt 0) { 'nicht geprüft' }
    else { 'durchgelassen (findings: ' + @($aclRes2.findings).Count + ', notes: ' + (@($aclRes2.notes) -join ' | ') + ')' }
  }

  # 4. Datenverzeichnis (check + apply/rollback mit WindowsPin) unter Kontrolle des Standardkontos
  Set-Content -LiteralPath (Join-Path $dataDir 'postgresql.conf') -Value "# base`n" -Encoding Ascii -NoNewline
  Set-Content -LiteralPath (Join-Path $dataDir 'postmaster.pid') -Value "1234`n$dataDir`n1700000000`n5432`n" -Encoding Ascii -NoNewline
  New-Junction (Join-Path $dataDir 'redir') $adminDir | Out-Null
  # Leeres Ausgabeverzeichnis, das dem Testkonto gehört: als --dir abzuweisen (sein Besitzer dürfte die ACL jederzeit ändern)
  New-Item -ItemType Directory -Path $foreignDir | Out-Null
  icacls $foreignDir /setowner "*$userSid" >$null

  $phpTest = @'
define('PG_HARDEN_LIBRARY', true);
require $argv[1];
set_error_handler(fn(int $no, string $msg, string $file, int $line): bool => throw new ErrorException($msg, 0, $no, $file, $line));
$dataDir = $argv[2];
$adminDir = $argv[3];
$journalDir = $argv[4];
$foreignDir = $argv[5];
$out = [];

try {
  Files::prepareDir($foreignDir);
  $out['foreign_dir'] = 'angenommen';
} catch (HardenException) {
  $out['foreign_dir'] = 'abgewiesen';
}

$out['pid_direct'] = Fs::readGuarded("$dataDir\\postmaster.pid", 4096, $dataDir) !== null ? 'gelesen' : 'abgewiesen';
$out['pid_junc'] = Fs::readGuarded("$dataDir\\redir\\pgpass.conf", 4096, $dataDir) === null ? 'abgewiesen' : 'gelesen';
$out['acl_direct'] = is_array(WindowsFacts::strictAcl("$dataDir\\postgresql.conf", $dataDir)) ? 'gelesen' : 'abgewiesen';
$out['acl_junc'] = WindowsFacts::strictAcl("$dataDir\\redir\\postgresql.conf", $dataDir) === null ? 'abgewiesen' : 'gelesen';

Files::prepareDir($journalDir);
$journal = new Journal($journalDir, ['tool' => 'admin-test']);
WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf", "$dataDir\\conf.d\\90-pg-harden.conf"]);
ServerFiles::makeDir("$dataDir\\conf.d", $dataDir);
$out['rename_pinned_data'] = Fs::attempt(fn() => rename($dataDir, $dataDir . '.moved')) === null ? 'gesperrt' : 'umbenannt';
$out['rename_pinned_confd'] = Fs::attempt(fn() => rename("$dataDir\\conf.d", "$dataDir\\conf.d.moved")) === null ? 'gesperrt' : 'umbenannt';
ServerFiles::create("$dataDir\\conf.d\\90-pg-harden.conf", "ssl = on\n", "$dataDir\\postgresql.conf");
$bak = $journal->backup("$dataDir\\postgresql.conf");
ServerFiles::overwrite("$dataDir\\postgresql.conf", "# gehärtet\n");
$problems = ServerFiles::restore([
  ['path' => "$dataDir\\postgresql.conf", 'action' => 'modified', 'backup' => $bak],
  ['path' => "$dataDir\\conf.d", 'action' => 'created', 'backup' => null],
  ['path' => "$dataDir\\conf.d\\90-pg-harden.conf", 'action' => 'created', 'backup' => null],
], $journalDir);
$out['restore_ok'] = $problems === [] && !file_exists("$dataDir\\conf.d") ? 'ok' : 'fehler';
WindowsPin::end();

// Under an active hold of the data directory: the refusal must come from the check of the way, not from a missing hold.
WindowsPin::begin([$dataDir], ["$dataDir\\postgresql.conf"]);
try {
  ServerFiles::overwrite("$dataDir\\redir\\postgresql.conf", "# überschrieben\n");
  $out['overwrite_junc'] = 'durchgelassen';
} catch (HardenException) {
  $out['overwrite_junc'] = 'abgewiesen';
}
try {
  ServerFiles::create("$dataDir\\redir\\neu.conf", "neu\n", "$dataDir\\postgresql.conf");
  $out['create_junc'] = 'durchgelassen';
} catch (HardenException) {
  $out['create_junc'] = 'abgewiesen';
}
WindowsPin::end();
echo json_encode($out, JSON_UNESCAPED_UNICODE);
'@
  $phpScriptFile = Join-Path $workRoot 'run-checks.php'
  # UTF-8 ohne Byte-Order-Mark: Set-Content -Encoding UTF8 setzt in Windows PowerShell 5.1 eine BOM vor "<?php", dann ist
  # declare(strict_types=1) nicht mehr die erste Anweisung und PHP bricht ab.
  [IO.File]::WriteAllText($phpScriptFile, "<?php`ndeclare(strict_types=1);`n" + $phpTest, (New-Object System.Text.UTF8Encoding($false)))
  $ErrorActionPreference = 'Continue'
  $rawOut = (& $phpPath $phpScriptFile $entryPoint $dataDir $adminDir $journalDir $foreignDir 2>&1 | Out-String)
  $ErrorActionPreference = 'Stop'
  $resJson = $null
  try { $resJson = $rawOut | ConvertFrom-Json } catch {}
  if ($null -eq $resJson) {
    Write-Host "FEHLER PHP-Prüfskript lieferte kein JSON:`n$rawOut" -ForegroundColor Red
    $resJson = [pscustomobject]@{}
  }

  Check-Case 'Files::prepareDir weist leeres Verzeichnis des Standardkontos ab' 'abgewiesen' { [string]$resJson.foreign_dir }

  Check-Case 'check: postmaster.pid direkt im Datenverzeichnis' 'gelesen' { [string]$resJson.pid_direct }
  Check-Case 'check: Lesen hinter Junction im Datenverzeichnis' 'abgewiesen' { [string]$resJson.pid_junc }
  Check-Case 'WindowsFacts::strictAcl direkt im Datenverzeichnis (über Handle)' 'gelesen' { [string]$resJson.acl_direct }
  Check-Case 'WindowsFacts::strictAcl hinter Junction im Datenverzeichnis' 'abgewiesen' { [string]$resJson.acl_junc }
  Check-Case 'WindowsPin sperrt Datenverzeichnis gegen Umbenennen' 'gesperrt' { [string]$resJson.rename_pinned_data }
  Check-Case 'WindowsPin sperrt neu angelegtes conf.d gegen Umbenennen' 'gesperrt' { [string]$resJson.rename_pinned_confd }
  Check-Case 'ServerFiles::restore spielt im gesperrten Verzeichnis sauber zurück' 'ok' { [string]$resJson.restore_ok }
  Check-Case 'ServerFiles::overwrite weist Junction im Datenverzeichnis ab' 'abgewiesen' { [string]$resJson.overwrite_junc }
  Check-Case 'ServerFiles::create weist Junction im Datenverzeichnis ab' 'abgewiesen' { [string]$resJson.create_junc }
  Check-Case 'Admin-Verzeichnis hinter allen Junctions unversehrt' 'unversehrt' {
    $c = (Get-Content -LiteralPath (Join-Path $adminDir 'postgresql.conf') -Raw).Trim()
    $noNew = -not (Test-Path -LiteralPath (Join-Path $adminDir 'neu.conf'))
    if ($c -eq '# admin-only' -and $noNew) { 'unversehrt' } else { 'verändert' }
  }
} finally {
  foreach ($l in $links) {
    Remove-JunctionSafe $l
  }
  # Das Testkonto meldet sich nie an, Windows legt also kein eigenes Profil an: zu entfernen ist nur der eigene ProfileList-Eintrag.
  if ($regKeyCreated -and (Test-Path -LiteralPath $regKeyPath)) {
    try {
      Remove-Item -LiteralPath $regKeyPath -Recurse -Force -ErrorAction Stop
    } catch {
      $script:failed++
      Write-Host "FEHLER ProfileList-Eintrag $regKeyPath ließ sich nicht entfernen ($($_.Exception.Message))" -ForegroundColor Red
    }
  }
  if ($userCreated) {
    try {
      Remove-LocalUser -Name $userName -ErrorAction Stop
      Write-Host "--     Testkonto wieder entfernt: $userName"
    } catch {
      $script:failed++
      Write-Host "FEHLER Testkonto $userName ließ sich nicht entfernen ($($_.Exception.Message)) — von Hand löschen: Remove-LocalUser -Name $userName" -ForegroundColor Red
    }
  }
  # rmdir /s folgt keiner Junction (entfernt nur den Link); die Junctions sind oben ohnehin schon entfernt.
  if (Test-Path -LiteralPath $workRoot) {
    cmd /c rmdir /s /q "`"$workRoot`"" >$null 2>&1
  }
  if (Test-Path -LiteralPath $workRoot) {
    Write-Host "FEHLER Arbeitsordner blieb liegen — von Hand in einer Administrator-PowerShell: cmd /c rmdir /s /q `"$workRoot`"" -ForegroundColor Red
  }
}

Check-Case 'Temporärer Arbeitsordner vollständig aufgeräumt' 'ja' { if (Test-Path -LiteralPath $workRoot) { 'nein' } else { 'ja' } }
if ($failed -gt 0) {
  [Console]::Error.WriteLine("FEHLER: $failed Prüfung(en) fehlgeschlagen.")
  exit 1
}
Write-Host 'Alle Admin-Prüfungen erfolgreich.' -ForegroundColor Green
exit 0
