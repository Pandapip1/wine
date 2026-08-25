# Capability probe: can a windows-latest runner give us an NTFS volume with a
# NON-DEFAULT cluster size?
#
# This answers ONLY that question.  It deliberately performs no SET_ZERO_DATA
# measurement, because the measurement's design depends on the answer and
# building it first would be building on an unverified foundation.
#
# Why the question matters: the 64 KB sparse deallocation granularity measured in
# run 32875115102 was measured on ONE volume, with 4 KB clusters.  Two rules fit
# every cell we have -- a constant 64 KB, or 16x the cluster size -- and they are
# indistinguishable without a volume whose cluster size differs.  A 1 KB-cluster
# volume separates them: constant predicts 64 KB, 16x predicts 16 KB.
#
# 1 KB is the right choice rather than 64 KB.  A 64 KB-cluster volume would make
# the 16x rule predict a 1 MB granularity, forcing a test file large enough that
# file size varies alongside cluster size -- reintroducing exactly the confound
# that produced the wrong deallocation rule earlier today.
#
# Every stage prints PASS or FAIL and keeps going, so one failure does not hide
# the state of everything after it.  A FAIL here is a real result: "unanswerable
# on this infrastructure" is actionable, a quietly weakened substitute cell is not.

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$script:VhdPath = Join-Path $env:TEMP "clustertest.vhdx"
$script:Verdict = @{}

function Stage([string]$name, [scriptblock]$body) {
  Write-Host ""
  Write-Host "=== STAGE: $name"
  try {
    $r = & $body
    if ($r -eq $false) { Write-Host "    FAIL: $name"; $script:Verdict[$name] = $false; return $false }
    Write-Host "    PASS: $name"
    $script:Verdict[$name] = $true
    return $true
  } catch {
    Write-Host ("    FAIL: $name -- {0}: {1}" -f $_.Exception.GetType().Name, $_.Exception.Message)
    $script:Verdict[$name] = $false
    return $false
  }
}

# --- STAGE 0: environment ----------------------------------------------------
Write-Host "=== STAGE: environment"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
             [Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "running as: $($id.Name)   elevated/admin: $isAdmin"
if (-not $isAdmin) {
  Write-Host "    NOTE: attaching a VHD requires administrator rights (Mount-DiskImage docs)."
}
Write-Host ""
Write-Host "--- free space ---"
Get-CimInstance Win32_LogicalDisk | Where-Object DriveType -eq 3 |
  Select-Object DeviceID,@{n='FreeGB';e={[math]::Round($_.FreeSpace/1GB,1)}},
                        @{n='SizeGB';e={[math]::Round($_.Size/1GB,1)}} | Format-Table -AutoSize

# Baseline: this also independently checks the premise behind every measurement
# taken so far, namely that the runner's working volume really is 4 KB clusters.
Write-Host "--- BASELINE cluster size of the volume all prior probes ran on ---"
foreach ($d in @('C:','D:')) {
  if (Test-Path $d) {
    $info = (fsutil fsinfo ntfsinfo $d 2>&1 | Out-String)
    $m = [regex]::Match($info, '(?im)^\s*Bytes Per Cluster\s*:\s*(\d+)')
    if ($m.Success) { Write-Host ("  {0}  Bytes Per Cluster = {1}" -f $d, $m.Groups[1].Value) }
    else            { Write-Host ("  {0}  (could not parse; not NTFS?)" -f $d) }
  }
}

# --- STAGE 1: which route is even available? ---------------------------------
$routeA = $false
$null = Stage "cmdlet-availability" {
  foreach ($c in @('New-VHD','Mount-VHD','Initialize-Disk','New-Partition','Format-Volume','Get-Disk')) {
    $have = [bool](Get-Command $c -ErrorAction SilentlyContinue)
    Write-Host ("    {0,-16} {1}" -f $c, $(if ($have) {'present'} else {'MISSING'}))
  }
  # New-VHD/Mount-VHD come from the Hyper-V PowerShell module.  Their absence is
  # not fatal -- diskpart's create/attach vdisk is a separate route that does not
  # need Hyper-V -- so this stage only records which routes are open.
  $script:routeA = [bool](Get-Command New-VHD -ErrorAction SilentlyContinue) -and
                   [bool](Get-Command Mount-VHD -ErrorAction SilentlyContinue)
  Write-Host ("    Route A (Hyper-V cmdlets): {0}" -f $(if ($script:routeA) {'available'} else {'not available'}))
  Write-Host  "    Route B (diskpart vdisk):  will be tried if Route A fails"
  Write-Host ("    diskpart present: {0}" -f [bool](Get-Command diskpart -ErrorAction SilentlyContinue))
  return $true
}

if (Test-Path $script:VhdPath) { Remove-Item $script:VhdPath -Force -ErrorAction SilentlyContinue }
$disksBefore = @(Get-Disk -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Number)
Write-Host "    disks before attach: $($disksBefore -join ',')"

# --- STAGE 2: Route A -- Hyper-V cmdlets -------------------------------------
$attached = $false
if ($script:routeA) {
  $attached = Stage "routeA-create-and-attach (New-VHD | Mount-VHD)" {
    New-VHD -Path $script:VhdPath -SizeBytes 1GB -Dynamic -ErrorAction Stop | Out-Null
    Write-Host "    created $script:VhdPath"
    Mount-VHD -Path $script:VhdPath -ErrorAction Stop | Out-Null
    Write-Host "    mounted"
    return $true
  }
} else {
  Write-Host ""
  Write-Host "=== STAGE: routeA-create-and-attach (New-VHD | Mount-VHD)"
  Write-Host "    SKIPPED: Hyper-V cmdlets absent"
  $script:Verdict['routeA-create-and-attach (New-VHD | Mount-VHD)'] = $false
}

# --- STAGE 3: Route B -- diskpart, no Hyper-V needed --------------------------
# Syntax per MS Learn "Create vdisk": create vdisk file=<path> maximum=<MB> type=expandable
if (-not $attached) {
  $attached = Stage "routeB-create-and-attach (diskpart)" {
    $s = Join-Path $env:TEMP "mkvdisk.txt"
    @(
      "create vdisk file=`"$script:VhdPath`" maximum=1024 type=expandable",
      "select vdisk file=`"$script:VhdPath`"",
      "attach vdisk"
    ) | Set-Content -Path $s -Encoding ASCII
    Write-Host "    diskpart script:"
    Get-Content $s | ForEach-Object { Write-Host "      $_" }
    $out = (diskpart /s $s 2>&1 | Out-String)
    Write-Host "    --- diskpart output ---"
    $out -split "`r?`n" | Where-Object { $_.Trim() } | ForEach-Object { Write-Host "      $_" }
    Remove-Item $s -Force -ErrorAction SilentlyContinue
    if ($LASTEXITCODE -ne 0) { Write-Host "    diskpart exit code $LASTEXITCODE"; return $false }
    return $true
  }
}

if (-not $attached) {
  Write-Host ""
  Write-Host "=========================================================="
  Write-Host "VERDICT: VHD-CAPABLE = NO"
  Write-Host "Neither route could create and attach a virtual disk on this runner."
  Write-Host "The cluster-size question is UNANSWERABLE on this infrastructure by"
  Write-Host "this method. Do not substitute a weaker cell: report it as unanswerable."
  Write-Host "=========================================================="
  exit 0
}

# --- STAGE 4: turn the attached disk into a 1 KB-cluster NTFS volume ---------
$script:Letter = $null
$null = Stage "initialize-partition-format (AllocationUnitSize 1024)" {
  $disksAfter = @(Get-Disk | Select-Object -ExpandProperty Number)
  $new = $disksAfter | Where-Object { $disksBefore -notcontains $_ }
  Write-Host "    disks after attach: $($disksAfter -join ',')   new: $($new -join ',')"
  if (-not $new) { Write-Host "    no new disk appeared despite a successful attach"; return $false }
  $n = $new[0]

  Initialize-Disk -Number $n -PartitionStyle GPT -ErrorAction SilentlyContinue | Out-Null
  $part = New-Partition -DiskNumber $n -AssignDriveLetter -UseMaximumSize -ErrorAction Stop
  $script:Letter = "$($part.DriveLetter):"
  Write-Host "    partition created, drive letter $script:Letter"

  # -AllocationUnitSize (alias ClusterSize) is a UInt32 on Format-Volume; NTFS
  # accepts 1024. Whether it is HONOURED is checked in the next stage, not assumed.
  Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS `
                -AllocationUnitSize 1024 -NewFileSystemLabel "CLUSTER1K" `
                -Confirm:$false -Force -ErrorAction Stop | Out-Null
  Write-Host "    formatted NTFS, requested AllocationUnitSize 1024"
  return $true
}

# --- STAGE 5: did the format actually honour the request? --------------------
# The crux. A format that silently rounded 1024 up to 4096 would look like a
# success and make every later measurement a duplicate of the ones we already
# have, while appearing to be a new data point. Verify, do not assert.
$clusterOk = $false
$null = Stage "verify-cluster-size-is-really-1024" {
  if (-not $script:Letter) { Write-Host "    no volume to check"; return $false }
  $info = (fsutil fsinfo ntfsinfo $script:Letter 2>&1 | Out-String)
  Write-Host "    --- fsutil fsinfo ntfsinfo $script:Letter ---"
  $info -split "`r?`n" | Where-Object { $_ -match 'Cluster|Sector|Version' } |
    ForEach-Object { Write-Host "      $($_.Trim())" }
  $m = [regex]::Match($info, '(?im)^\s*Bytes Per Cluster\s*:\s*(\d+)')
  if (-not $m.Success) { Write-Host "    could not parse Bytes Per Cluster"; return $false }
  $bpc = [int]$m.Groups[1].Value
  Write-Host ("    MEASURED Bytes Per Cluster = {0} (requested 1024)" -f $bpc)
  if ($bpc -ne 1024) {
    Write-Host "    The request was NOT honoured. A measurement here would silently"
    Write-Host "    repeat the 4 KB volume we already have."
    return $false
  }
  $script:clusterOk = $true
  return $true
}

# --- STAGE 6: can the volume carry the experiment at all? --------------------
# A 1 KB-cluster volume is useless to us if sparse files do not work on it.
# This checks the mechanism only -- it takes no granularity measurement.
$null = Stage "sparse-file-support-on-that-volume" {
  if (-not $script:clusterOk) { Write-Host "    skipped: no verified 1 KB volume"; return $false }
  $f = Join-Path $script:Letter "sparsecheck.bin"
  fsutil file createnew $f 1048576 2>&1 | Out-Null
  $set = (fsutil sparse setflag $f 2>&1 | Out-String).Trim()
  $qry = (fsutil sparse queryflag $f 2>&1 | Out-String).Trim()
  Write-Host "    setflag  : $set"
  Write-Host "    queryflag: $qry"
  Remove-Item $f -Force -ErrorAction SilentlyContinue
  if ($qry -notmatch 'is set|This file is set as sparse') {
    Write-Host "    sparse flag did not stick on this volume"
    return $false
  }
  return $true
}

# --- verdict -----------------------------------------------------------------
Write-Host ""
Write-Host "=========================================================="
Write-Host "STAGE RESULTS"
foreach ($k in $script:Verdict.Keys) {
  Write-Host ("  {0,-48} {1}" -f $k, $(if ($script:Verdict[$k]) {'PASS'} else {'FAIL'}))
}
Write-Host ""
if ($script:clusterOk -and $script:Verdict['sparse-file-support-on-that-volume']) {
  Write-Host "VERDICT: VHD-CAPABLE = YES, and a 1 KB-cluster NTFS volume with working"
  Write-Host "sparse files is reachable at $script:Letter on windows-latest."
  Write-Host "The cluster-size question IS answerable here. Next step is the"
  Write-Host "granularity measurement on that volume -- 64 KB released => constant rule,"
  Write-Host "16 KB released => 16x-cluster rule."
} else {
  Write-Host "VERDICT: VHD-CAPABLE = PARTIAL/NO -- see the failing stage above."
  Write-Host "Do not weaken the experiment to fit. Report what is not reachable."
}
Write-Host "=========================================================="

# --- cleanup ------------------------------------------------------------------
try {
  if ($script:routeA -and (Get-Command Dismount-VHD -ErrorAction SilentlyContinue)) {
    Dismount-VHD -Path $script:VhdPath -ErrorAction SilentlyContinue
  } else {
    $s = Join-Path $env:TEMP "rmvdisk.txt"
    @("select vdisk file=`"$script:VhdPath`"", "detach vdisk") | Set-Content -Path $s -Encoding ASCII
    diskpart /s $s 2>&1 | Out-Null
    Remove-Item $s -Force -ErrorAction SilentlyContinue
  }
  Remove-Item $script:VhdPath -Force -ErrorAction SilentlyContinue
  Write-Host "cleanup: detached and removed $script:VhdPath"
} catch {
  Write-Host "cleanup: $($_.Exception.Message)"
}
