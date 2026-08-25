# Measure the FSCTL_SET_ZERO_DATA deallocation granularity as a function of the
# volume's cluster size.
#
# Established so far (run 32875115102, on a 4096-byte-cluster volume): storage is
# released only for whole 65536-byte-aligned units inside the zeroed range. One
# aligned 64 KB unit released 64 KB; one 4 KB cluster, a 60 KB run ending on a
# unit boundary, and a misaligned 64 KB run all released nothing.
#
# That single volume cannot distinguish two rules which fit it equally well:
#   (a) the granularity is a CONSTANT 65536 bytes
#   (b) the granularity is 16 x the cluster size (16 x 4096 = 65536)
# This script measures the granularity again on volumes whose cluster size is NOT
# 4096, where the two rules give different numbers. It does not assume which is
# right, and deliberately states no expected outcome.
#
# HOW THE GRANULARITY IS MEASURED, rather than guessed at:
# For a candidate size Gc, zero the range [Gc, 2*Gc) -- aligned to Gc, length Gc --
# in a fresh 1 MB file, and record how much allocation is released.
#   * If Gc < G, the range is shorter than one granularity unit, so it cannot
#     contain a whole one and must release 0.
#   * If Gc >= G and Gc is a multiple of G (all candidates are powers of two, as
#     is any plausible G), the range is exactly a whole number of aligned units
#     and releases Gc.
# So walking Gc upward, THE SMALLEST Gc THAT RELEASES ANYTHING IS THE GRANULARITY.
# This reads G off directly instead of testing one hypothesis at a time.
#
# The file size is held at 1 MB in every cell of every regime, so cluster size is
# the only thing that varies. Letting file size move with it is what produced a
# wrong deallocation rule earlier in this investigation.
#
# NOTE ON OUTPUT: Write-Host everywhere, never Write-Output -- inside a function
# Write-Output is captured by the caller's assignment instead of printed.

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$cs = @"
using System; using System.Runtime.InteropServices;
public class ZC {
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool DeviceIoControl(IntPtr h, uint code, IntPtr inb, uint inl,
    IntPtr outb, uint outl, out uint ret, IntPtr ov);
  [DllImport("ntdll.dll")]
  public static extern int NtQueryInformationFile(IntPtr h, byte[] iosb, byte[] inf, uint len, int cls);
  [DllImport("ntdll.dll")]
  public static extern int NtFsControlFile(IntPtr h, IntPtr ev, IntPtr apc, IntPtr ctx,
    byte[] iosb, uint code, IntPtr inb, uint inl, IntPtr outb, uint outl);
  [StructLayout(LayoutKind.Sequential)] public struct ZD { public long Offset; public long Beyond; }
  public const uint FSCTL_SET_SPARSE             = 0x000900C4;
  public const uint FSCTL_SET_ZERO_DATA          = 0x000980C8;
  public const uint FSCTL_QUERY_ALLOCATED_RANGES = 0x000940CF;

  public static long AllocOf(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[24];
    NtQueryInformationFile(h, io, b, 24, 5);
    return BitConverter.ToInt64(b,0);
  }
  public static long EofOf(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[24];
    NtQueryInformationFile(h, io, b, 24, 5);
    return BitConverter.ToInt64(b,8);
  }
  public static int ZeroData(IntPtr h, long off, long beyond) {
    ZD z = new ZD(); z.Offset = off; z.Beyond = beyond;
    int sz = Marshal.SizeOf(typeof(ZD));
    IntPtr p = Marshal.AllocHGlobal(sz);
    Marshal.StructureToPtr(z, p, false);
    byte[] io = new byte[16];
    int st = NtFsControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, io,
                             FSCTL_SET_ZERO_DATA, p, (uint)sz, IntPtr.Zero, 0);
    Marshal.FreeHGlobal(p);
    return st;
  }
  public static string Ranges(IntPtr h, long eof) {
    ZD q = new ZD(); q.Offset = 0; q.Beyond = eof;
    int sz = Marshal.SizeOf(typeof(ZD));
    IntPtr pin = Marshal.AllocHGlobal(sz);
    Marshal.StructureToPtr(q, pin, false);
    IntPtr pout = Marshal.AllocHGlobal(sz * 128);
    uint ret = 0;
    bool ok = DeviceIoControl(h, FSCTL_QUERY_ALLOCATED_RANGES, pin, (uint)sz,
                              pout, (uint)(sz*128), out ret, IntPtr.Zero);
    string s = ok ? "" : ("query failed err=" + Marshal.GetLastWin32Error());
    if (ok) {
      int n = (int)(ret / sz);
      if (n == 0) s = "<none: fully sparse>";
      for (int i = 0; i < n && i < 12; i++) {
        long o = Marshal.ReadInt64(pout, i*sz);
        long b = Marshal.ReadInt64(pout, i*sz + 8);
        s += string.Format("[{0},{1}) ", o, o+b);
      }
      if (n > 12) s += "...(" + n + " extents)";
    }
    Marshal.FreeHGlobal(pin); Marshal.FreeHGlobal(pout);
    return s;
  }
  public static bool MarkSparse(IntPtr h) {
    uint r = 0;
    return DeviceIoControl(h, FSCTL_SET_SPARSE, IntPtr.Zero, 0, IntPtr.Zero, 0, out r, IntPtr.Zero);
  }
}
"@
Add-Type -TypeDefinition $cs

$FILESIZE = 1048576   # held constant across every cell and every regime

function New-PatternFile([string]$path) {
  if (Test-Path $path) { Remove-Item $path -Force -ErrorAction SilentlyContinue }
  $fs = [System.IO.File]::Open($path,'Create','ReadWrite','None')
  $h  = $fs.SafeFileHandle.DangerousGetHandle()
  if (-not [ZC]::MarkSparse($h)) { Write-Host "      WARNING: FSCTL_SET_SPARSE failed" }
  $chunk = New-Object byte[] 65536
  for ($i=0; $i -lt 65536; $i++) { $chunk[$i] = 0x78 }
  $left = $FILESIZE
  while ($left -gt 0) { $n = [Math]::Min($left,65536); $fs.Write($chunk,0,$n); $left -= $n }
  $fs.Flush($true)
  return $fs
}

# Returns bytes released, or -1 if the FSCTL itself failed.
function Measure-Cell([string]$vol, [string]$tag, [int]$cluster, [long]$off, [long]$beyond) {
  $p = Join-Path $vol "zc-$tag.bin"
  $fs = New-PatternFile $p
  $h = $fs.SafeFileHandle.DangerousGetHandle()
  $a0 = [ZC]::AllocOf($h)
  $e0 = [ZC]::EofOf($h)
  $st = [ZC]::ZeroData($h,$off,$beyond)
  $a1 = [ZC]::AllocOf($h)
  $e1 = [ZC]::EofOf($h)
  $rel = $a0 - $a1
  Write-Host ("  cluster={0,-6} {1,-14} ZERO_DATA({2},{3}) len={4,-7} st=0x{5:x8}  alloc {6} -> {7}  RELEASED={8}" -f `
              $cluster, $tag, $off, $beyond, ($beyond-$off), $st, $a0, $a1, $rel)
  if ($e1 -ne $e0) { Write-Host ("      NOTE: EndOfFile changed {0} -> {1}" -f $e0, $e1) }
  if ($st -ne 0)   { Write-Host ("      NOTE: FSCTL returned nonzero status"); $rel = -1 }
  Write-Host ("      extents after: {0}" -f [ZC]::Ranges($h,$FILESIZE))
  $fs.Close(); Remove-Item $p -Force -ErrorAction SilentlyContinue
  return $rel
}

function Measure-Regime([string]$vol, [int]$cluster) {
  Write-Host ""
  Write-Host "=========================================================="
  Write-Host "=== MEASURING on $vol -- VERIFIED cluster size $cluster bytes, file size $FILESIZE"
  Write-Host "=========================================================="

  # POSITIVE CONTROL. Zeroing the entire file must release a large amount on any
  # volume where the FSCTL deallocates at all. If this releases nothing, the whole
  # ladder below would read as "granularity larger than every candidate" when the
  # real cause is that deallocation does not work here -- two very different
  # findings that produce identical ladders.
  Write-Host "--- positive control: zero the whole file ---"
  $ctl = Measure-Cell $vol "control-whole" $cluster 0 $FILESIZE
  if ($ctl -le 0) {
    Write-Host ""
    Write-Host "  CONTROL FAILED: zeroing the entire file released $ctl bytes."
    Write-Host "  The ladder below cannot be interpreted on this volume. Do not read"
    Write-Host "  an all-zero ladder as 'granularity is large' -- it is not measurable here."
    return
  }
  Write-Host "  control OK: deallocation works on this volume."

  # The ladder. Each cell is [Gc, 2*Gc): aligned to Gc, exactly Gc long.
  Write-Host ""
  Write-Host "--- granularity ladder: smallest Gc that releases anything IS the granularity ---"
  $ladder = @(1024,2048,4096,8192,16384,32768,65536,131072,262144)
  $found = 0
  foreach ($gc in $ladder) {
    $rel = Measure-Cell $vol ("gc-" + $gc) $cluster $gc (2*$gc)
    if ($rel -gt 0 -and $found -eq 0) { $found = $gc }
  }

  Write-Host ""
  Write-Host ("RESULT for cluster size {0}: granularity = {1}" -f $cluster, $(if($found){$found}else{'NOT FOUND within the ladder'}))
  if ($found) {
    Write-Host ("  16 x cluster would be {0}; a constant rule would be 65536." -f (16*$cluster))
    Write-Host  "  Reported without interpretation -- compare across regimes before concluding."
  }
}

# --- build the volumes --------------------------------------------------------
# Same construction as the capability probe, including the read-back check: a
# format that silently rounded the cluster size would produce a measurement that
# duplicates an existing regime while carrying a new label.
function Build-Volume([string]$Tag, [int]$PhysSector, [int]$LogSector, [int]$AllocUnit) {
  $vhd = Join-Path $env:TEMP "meas-$Tag.vhdx"
  if (Test-Path $vhd) { Remove-Item $vhd -Force -ErrorAction SilentlyContinue }
  $before = @(Get-Disk -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Number)
  try {
    $vhdArgs = @{ Path = $vhd; SizeBytes = 1GB; Dynamic = $true; ErrorAction = 'Stop' }
    if ($PhysSector) { $vhdArgs['PhysicalSectorSizeBytes'] = $PhysSector }
    if ($LogSector)  { $vhdArgs['LogicalSectorSizeBytes']  = $LogSector }
    New-VHD @vhdArgs | Out-Null
    Mount-VHD -Path $vhd -ErrorAction Stop | Out-Null
    $after = @(Get-Disk | Select-Object -ExpandProperty Number)
    $new = @($after | Where-Object { $before -notcontains $_ })
    if (-not $new) { throw "no new disk after mount" }
    Initialize-Disk -Number $new[0] -PartitionStyle GPT -ErrorAction SilentlyContinue | Out-Null
    $part = New-Partition -DiskNumber $new[0] -AssignDriveLetter -UseMaximumSize -ErrorAction Stop
    Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS -AllocationUnitSize $AllocUnit `
                  -NewFileSystemLabel $Tag -Confirm:$false -Force -ErrorAction Stop | Out-Null
    $letter = "$($part.DriveLetter):"
    $info = (fsutil fsinfo ntfsinfo $letter 2>&1 | Out-String)
    $m = [regex]::Match($info, '(?im)^\s*Bytes Per Cluster\s*:\s*(\d+)')
    $bpc = if ($m.Success) { [int]$m.Groups[1].Value } else { 0 }
    Write-Host ("[$Tag] drive $letter  requested cluster $AllocUnit  ACHIEVED $bpc")
    if ($bpc -ne $AllocUnit) {
      Write-Host "[$Tag] SKIPPING: achieved cluster size differs from the request; a"
      Write-Host "[$Tag] measurement here would silently duplicate another regime."
      Dismount-VHD -Path $vhd -ErrorAction SilentlyContinue
      Remove-Item $vhd -Force -ErrorAction SilentlyContinue
      return $null
    }
    return @{ Letter = $letter; Cluster = $bpc; Vhd = $vhd }
  } catch {
    Write-Host ("[$Tag] setup FAILED -- {0}: {1}" -f $_.Exception.GetType().Name, $_.Exception.Message)
    Dismount-VHD -Path $vhd -ErrorAction SilentlyContinue
    Remove-Item $vhd -Force -ErrorAction SilentlyContinue
    return $null
  }
}

Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host ""

# Regime 0: the runner's own 4096-cluster volume. This re-measures the ESTABLISHED
# case with the same ladder, so the new instrument is checked against a known
# answer before its readings on unfamiliar volumes are trusted.
$tempVol = ($env:TEMP.Substring(0,2))
$i0 = (fsutil fsinfo ntfsinfo $tempVol 2>&1 | Out-String)
$m0 = [regex]::Match($i0, '(?im)^\s*Bytes Per Cluster\s*:\s*(\d+)')
if ($m0.Success) {
  Measure-Regime $tempVol ([int]$m0.Groups[1].Value)
} else {
  Write-Host "could not read the cluster size of $tempVol; skipping the baseline regime"
}

foreach ($r in @(
    @{ Tag='cluster8k'; Phys=0;   Log=0;   Alloc=8192 },
    @{ Tag='cluster1k'; Phys=512; Log=512; Alloc=1024 })) {
  $v = Build-Volume $r.Tag $r.Phys $r.Log $r.Alloc
  if ($v) {
    Measure-Regime $v.Letter $v.Cluster
    Dismount-VHD -Path $v.Vhd -ErrorAction SilentlyContinue
    Remove-Item $v.Vhd -Force -ErrorAction SilentlyContinue
    Write-Host "[$($r.Tag)] detached"
  }
}

Write-Host ""
Write-Host "=========================================================="
Write-Host "Compare the RESULT lines across regimes. If the granularity is the same"
Write-Host "number in every regime, it does not track cluster size. If it scales with"
Write-Host "cluster size, it does. A regime that failed to build proves nothing either way."
Write-Host "=========================================================="
