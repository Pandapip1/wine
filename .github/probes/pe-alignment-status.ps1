$ErrorActionPreference = "Stop"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
Write-Host ("PowerShell process is 64-bit: {0}" -f [System.Environment]::Is64BitProcess)
Write-Host ""

# What does this kernel do with a PE whose SectionAlignment is smaller than the
# page size?  Eight prebuilt images (see .github/probes/images/README) are
# exercised, in two halves that differ only on the machine axis:
#
#   i386 half  -- Machine 0x014c / Magic 0x010b (PE32).  On an x64 runner these
#                 go through WOW64; the answer they give is about the WOW64
#                 path, not about the native 64-bit loader.
#   x86-64 half -- Machine 0x8664 / Magic 0x020b (PE32+).  These go through the
#                 native 64-bit loader.
#
# Each half carries its OWN positive control, run first in that half.  A 32-bit
# control says nothing about whether the harness reaches the 64-bit loader, so
# the two controls are not interchangeable and neither validates the other's
# cells.  For each cell, raw:
#   - sha256 measured on the runner, against the sha256 recorded in the README,
#     so a mangled checkout is visible rather than silent
#   - SectionAlignment / FileAlignment / Subsystem / Magic / Machine /
#     SizeOfImage parsed here out of the file's own bytes, not taken on trust
#   - CreateProcessW's BOOL and GetLastError()
#   - the NTSTATUS from NtCreateSection(SEC_IMAGE) on a handle to the file --
#     the operation that maps the file as an image, the same one process
#     creation performs
#   - the NTSTATUS from NtCreateSection(SEC_COMMIT) on the same file, as a
#     control on the axis: it separates "this file object cannot back a section
#     at all" from "the image format was rejected".
# No verdict is computed for any cell except the harness positive control.

$cs = @"
using System; using System.Runtime.InteropServices;
public class P {
  [StructLayout(LayoutKind.Sequential)] public struct PROCESS_INFORMATION {
    public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
  }
  [StructLayout(LayoutKind.Sequential)] public struct STARTUPINFO {
    public uint cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
    public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
    public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags;
    public ushort wShowWindow; public ushort cbReserved2; public IntPtr lpReserved2;
    public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
  }

  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern bool CreateProcessW(string app, string cmd, IntPtr pa, IntPtr ta,
    bool inherit, uint flags, IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
    uint disp, uint flags, IntPtr templ);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool TerminateProcess(IntPtr h, uint code);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern uint WaitForSingleObject(IntPtr h, uint ms);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);
  [DllImport("ntdll.dll")]
  public static extern int NtCreateSection(out IntPtr sec, uint access, IntPtr oa,
    IntPtr maxsize, uint prot, uint attrs, IntPtr file);

  public const uint CREATE_SUSPENDED = 0x00000004;
  public const uint CREATE_NO_WINDOW = 0x08000000;
  public const uint GENERIC_READ     = 0x80000000;
  public const uint GENERIC_EXECUTE  = 0x20000000;
  public const uint SEC_IMAGE        = 0x01000000;
  public const uint SEC_COMMIT       = 0x08000000;
  public const uint PAGE_READONLY    = 0x00000002;
  public const uint SECTION_ALL_ACCESS = 0x000F001F;

  // Anti-hang: the process is created SUSPENDED, so a cell that really is a
  // working image never executes a single instruction; it is terminated at once
  // and waited for with a bounded timeout.
  public static string Launch(string path) {
    STARTUPINFO si = new STARTUPINFO();
    si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
    PROCESS_INFORMATION pi;
    bool ok = CreateProcessW(path, null, IntPtr.Zero, IntPtr.Zero, false,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);
    int err = Marshal.GetLastWin32Error();
    string extra = "";
    if (ok) {
      bool killed = TerminateProcess(pi.hProcess, 0xdead);
      uint w = WaitForSingleObject(pi.hProcess, 5000);
      extra = string.Format("  [pid={0} created suspended; TerminateProcess={1} wait=0x{2:x}]",
                            pi.dwProcessId, killed, w);
      CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return string.Format("CreateProcessW={0,-5} GetLastError={1} (0x{1:x8}){2}", ok, err, extra);
  }

  public static bool LaunchOk(string path) {
    STARTUPINFO si = new STARTUPINFO();
    si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
    PROCESS_INFORMATION pi;
    bool ok = CreateProcessW(path, null, IntPtr.Zero, IntPtr.Zero, false,
                             CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi);
    if (ok) {
      TerminateProcess(pi.hProcess, 0xdead);
      WaitForSingleObject(pi.hProcess, 5000);
      CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return ok;
  }

  // The handle must carry FILE_EXECUTE, which SEC_IMAGE requires; a .NET
  // FileStream handle does not have it, hence CreateFileW by hand.
  public static IntPtr OpenExec(string path) {
    return CreateFileW(path, GENERIC_READ | GENERIC_EXECUTE, 1 | 2, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
  }

  public static string Section(string path, uint attrs, string label) {
    IntPtr h = OpenExec(path);
    if (h == (IntPtr)(-1) || h == IntPtr.Zero)
      return string.Format("{0}: CreateFileW(GENERIC_READ|GENERIC_EXECUTE) failed, GetLastError={1}",
                           label, Marshal.GetLastWin32Error());
    IntPtr sec;
    int st = NtCreateSection(out sec, SECTION_ALL_ACCESS, IntPtr.Zero, IntPtr.Zero,
                             PAGE_READONLY, attrs, h);
    if (st >= 0) CloseHandle(sec);
    CloseHandle(h);
    return string.Format("{0}: NTSTATUS = 0x{1:x8}", label, st);
  }

  public static bool SectionOk(string path, uint attrs) {
    IntPtr h = OpenExec(path);
    if (h == (IntPtr)(-1) || h == IntPtr.Zero) return false;
    IntPtr sec;
    int st = NtCreateSection(out sec, SECTION_ALL_ACCESS, IntPtr.Zero, IntPtr.Zero,
                             PAGE_READONLY, attrs, h);
    if (st >= 0) CloseHandle(sec);
    CloseHandle(h);
    return st >= 0;
  }
}
"@
Add-Type -TypeDefinition $cs

# Images live next to this script, in the repo -- resolved relative to the
# script, never from an absolute path off the runner.
$here = $PSScriptRoot
if (-not $here) { $here = Split-Path -Parent $MyInvocation.MyCommand.Path }
$imgDir = Join-Path $here "images"
Write-Host "image directory: $imgDir"
if (-not (Test-Path $imgDir)) {
  Write-Host "IMAGE DIRECTORY NOT FOUND -- nothing can be measured; this run is void."
  exit 1
}

# sha256 as recorded in images/README, so a mangled checkout is loud.
$expected = @{
  # i386 / PE32
  "subpage20.exe"      = "489368B986CA21AE98486A2A7989A5E1FC756A17C6B80FB34B90401D5122B863"
  "subpage200.exe"     = "75C10877D50BBA918D3751701EF07457B789E1743433807AAF9EB18C438A9B5A"
  "native20.exe"       = "A3F7B535E1BFC753D920478035EDDC130C25FC1361321D5B6722A8E528CF1B2C"
  "default.exe"        = "B3B4817F4B8BF0688AF96A2652F026AD71C19ED8D2AC82DF38263F710D67AD0F"
  # x86-64 / PE32+
  "subpage20-x64.exe"  = "2EDA85779DD62AFA981EF2966CF852257F2AFABBF95B2234852F95BD328B5DF7"
  "subpage200-x64.exe" = "5679901CCF4EC0F73AB5A865C73AA8EC4F3DB823991599D7E5B6C73564FA2888"
  "native20-x64.exe"   = "3D791D9A5630587C8898902DFC62D0F12DA13DB3C6408A4D353451901C0995EF"
  "default-x64.exe"    = "D0522B6FF583CAD0CCA00DDDFE44468DAB8070CF6CCFE4983D862AC424932EAB"
}

$dir = Join-Path $env:TEMP "pe-alignment-probe"
if (Test-Path $dir) { Remove-Item $dir -Recurse -Force }
New-Item -ItemType Directory -Path $dir | Out-Null
Write-Host "probe directory: $dir"
Write-Host ""

function HexHead([byte[]]$b, [int]$n) {
  if ($b.Length -eq 0) { return "<none>" }
  $take = [Math]::Min($n, $b.Length)
  $s = ""
  for ($i = 0; $i -lt $take; $i++) { $s += ("{0:x2} " -f $b[$i]) }
  if ($b.Length -gt $take) { $s += "..." }
  return $s.Trim()
}

function MachineName([int]$v) {
  switch ($v) {
    0x014c { return "IMAGE_FILE_MACHINE_I386" }
    0x8664 { return "IMAGE_FILE_MACHINE_AMD64" }
    default { return "unnamed here" }
  }
}

function MagicName([int]$v) {
  switch ($v) {
    0x010b { return "PE32" }
    0x020b { return "PE32+" }
    default { return "unnamed here" }
  }
}

function SubsystemName([int]$v) {
  switch ($v) {
    1 { return "IMAGE_SUBSYSTEM_NATIVE" }
    2 { return "IMAGE_SUBSYSTEM_WINDOWS_GUI" }
    3 { return "IMAGE_SUBSYSTEM_WINDOWS_CUI" }
    default { return "unnamed here" }
  }
}

# Parse the headers out of the bytes on the runner.  Every number printed by
# this function was read from the file, not copied from a table.
function ShowHeaders([byte[]]$b) {
  if ($b.Length -lt 0x40) {
    Write-Host "    HEADERS: file is shorter than IMAGE_DOS_HEADER -- cannot parse"
    return
  }
  $e_magic = [System.BitConverter]::ToUInt16($b, 0)
  $lfanew  = [System.BitConverter]::ToUInt32($b, 0x3c)
  Write-Host ("    e_magic = 0x{0:x4}   e_lfanew = 0x{1:x}" -f $e_magic, $lfanew)
  if ($lfanew + 4 + 20 + 0x44 -gt $b.Length) {
    Write-Host "    HEADERS: e_lfanew puts the COFF/optional header out of range -- cannot parse"
    return
  }
  $sig = [System.BitConverter]::ToUInt32($b, $lfanew)
  $coff = [int]$lfanew + 4
  $machine  = [System.BitConverter]::ToUInt16($b, $coff)
  $nsec     = [System.BitConverter]::ToUInt16($b, $coff + 2)
  $sizeopt  = [System.BitConverter]::ToUInt16($b, $coff + 16)
  $chars    = [System.BitConverter]::ToUInt16($b, $coff + 18)
  $opt      = $coff + 20
  $magic    = [System.BitConverter]::ToUInt16($b, $opt)
  # SectionAlignment/FileAlignment/SizeOfImage/Subsystem sit at the same
  # offsets in IMAGE_OPTIONAL_HEADER32 and 64.
  $sectAlign = [System.BitConverter]::ToUInt32($b, $opt + 32)
  $fileAlign = [System.BitConverter]::ToUInt32($b, $opt + 36)
  $sizeImage = [System.BitConverter]::ToUInt32($b, $opt + 56)
  $subsys    = [System.BitConverter]::ToUInt16($b, $opt + 68)
  Write-Host ("    PE signature = 0x{0:x8}   Machine = 0x{1:x4} ({2})   NumberOfSections = {3}" -f $sig, $machine, (MachineName $machine), $nsec)
  Write-Host ("    SizeOfOptionalHeader = 0x{0:x}   Characteristics = 0x{1:x4}   Magic = 0x{2:x4} ({3})" -f $sizeopt, $chars, $magic, (MagicName $magic))
  Write-Host ("    SectionAlignment = 0x{0:x}   FileAlignment = 0x{1:x}" -f $sectAlign, $fileAlign)
  Write-Host ("    SizeOfImage = 0x{0:x}   Subsystem = {1} ({2})" -f $sizeImage, $subsys, (SubsystemName $subsys))
}

# Emit one cell.  Everything printed here is a raw measurement.
function Cell([string]$name, [string]$what, [int]$wantMachine, [int]$wantMagic, [string]$note) {
  $src = Join-Path $imgDir $name
  Write-Host "=== [$name] $what"
  if (-not (Test-Path $src)) {
    Write-Host "    MISSING from the checkout -- this cell measures nothing."
    Write-Host ""
    return
  }
  $p = Join-Path $dir $name
  Copy-Item $src $p -Force
  $bytes = [System.IO.File]::ReadAllBytes($p)
  $h = (Get-FileHash -Path $p -Algorithm SHA256).Hash
  $want = $expected[$name]
  Write-Host ("    length on disk = {0}" -f $bytes.Length)
  Write-Host ("    sha256 measured = {0}" -f $h)
  if ($want -and ($h -ne $want)) {
    Write-Host ("    sha256 recorded = {0}" -f $want)
    Write-Host "    HASH MISMATCH -- the file on the runner is not the file that was committed."
    Write-Host "    This cell does not measure what its name says."
  } else {
    Write-Host "    sha256 matches the value recorded in images/README"
  }
  Write-Host ("    bytes: {0}" -f (HexHead $bytes 24))
  ShowHeaders $bytes
  # Cross-check the parsed machine/magic against what images/README records for
  # this cell.  A disagreement is a FINDING about the committed file, not
  # something for this script to reconcile.
  if ($bytes.Length -ge 0x40) {
    $lf2 = [System.BitConverter]::ToUInt32($bytes, 0x3c)
    if ($lf2 + 4 + 20 + 0x44 -le $bytes.Length) {
      $m2 = [System.BitConverter]::ToUInt16($bytes, [int]$lf2 + 4)
      $g2 = [System.BitConverter]::ToUInt16($bytes, [int]$lf2 + 24)
      if ($wantMachine -ne 0 -and $m2 -ne $wantMachine) {
        Write-Host ("    HEADER DISAGREEMENT: parsed Machine = 0x{0:x4}, images/README records 0x{1:x4}." -f $m2, $wantMachine)
        Write-Host "    The committed file is not the file the README describes.  Report this; do not reconcile it."
      }
      if ($wantMagic -ne 0 -and $g2 -ne $wantMagic) {
        Write-Host ("    HEADER DISAGREEMENT: parsed Magic = 0x{0:x4}, images/README records 0x{1:x4}." -f $g2, $wantMagic)
        Write-Host "    The committed file is not the file the README describes.  Report this; do not reconcile it."
      }
    }
  }
  Write-Host ("    {0}" -f [P]::Launch($p))
  Write-Host ("    {0}" -f [P]::Section($p, [P]::SEC_IMAGE,  "NtCreateSection SEC_IMAGE "))
  Write-Host ("    {0}" -f [P]::Section($p, [P]::SEC_COMMIT, "NtCreateSection SEC_COMMIT"))
  if ($note) { Write-Host ("    NOTE: {0}" -f $note) }
  Write-Host ""
}

# One positive control check, applied separately to each half.  It is a check,
# not a prediction: it asks only whether an ORDINARILY aligned image from the
# same toolchain and the same machine type gets through this harness.
function ControlBanner([string]$file, [string]$half) {
  $ctlLaunch  = [P]::LaunchOk((Join-Path $dir $file))
  $ctlSection = [P]::SectionOk((Join-Path $dir $file), [P]::SEC_IMAGE)
  if ($ctlLaunch -and $ctlSection) {
    Write-Host ("    POSITIVE CONTROL PASS ({0}): {1} maps as SEC_IMAGE and launches" -f $half, $file)
    Write-Host ("    through this harness.  The harness therefore reaches the {0} loader, and a" -f $half)
    Write-Host ("    different result on another {0} cell is about that cell, not about the harness." -f $half)
  } else {
    Write-Host ("    POSITIVE CONTROL FAIL ({0}): LaunchOk={1} SectionOk(SEC_IMAGE)={2}" -f $half, $ctlLaunch, $ctlSection)
    Write-Host ("    THE {0} HALF OF THIS RUN IS VOID -- ignore every {0} cell." -f $half)
  }
}

Write-Host "##############################################################################"
Write-Host "########## HALF 1 of 2: i386 / PE32 images -- the WOW64 path         ##########"
Write-Host "##############################################################################"
Write-Host ""
Write-Host "  Every image in this half is Machine 0x014c / Magic 0x010b (PE32) -- verify"
Write-Host "  that in each cell's parsed header rather than taking it from this banner."
Write-Host "  The CI runner is x64, so CreateProcessW on these files goes through WOW64."
Write-Host "  Whatever this half reports is an answer about the WOW64 loader path.  It is"
Write-Host "  NOT an answer about the native 64-bit loader; that is what HALF 2 is for."
Write-Host ""

Write-Host "########## i386 positive control ##########"
Write-Host ""
# An image from the same toolchain and the same source, differing from the
# other i386 cells only on the alignment axis under test.  If this one does not
# map as SEC_IMAGE and launch, the i386 half is broken and every i386 number in
# this run is meaningless.
Cell "default.exe" "i386: SectionAlignment 0x1000 / FileAlignment 0x200 -- ordinary alignment" 0x014c 0x010b ""
ControlBanner "default.exe" "i386"
Write-Host ""

Write-Host "########## i386 sub-page SectionAlignment ##########"
Write-Host ""

Cell "subpage200.exe" "i386: SectionAlignment == FileAlignment == 0x200, Subsystem 3" 0x014c 0x010b ""
Cell "subpage20.exe"  "i386: SectionAlignment == FileAlignment == 0x20, Subsystem 3"  0x014c 0x010b ""
Cell "native20.exe"   "i386: SectionAlignment == FileAlignment == 0x20, Subsystem 1 (native)" 0x014c 0x010b @"
this image declares Subsystem 1.  CreateProcessW does not create user-mode
      processes from native-subsystem images, so its CreateProcessW result is
      uninformative about alignment and must not be recorded as a finding on
      that axis.  Only the NtCreateSection(SEC_IMAGE) line above is on-axis for
      this cell.
"@

Write-Host "##############################################################################"
Write-Host "########## HALF 2 of 2: x86-64 / PE32+ images -- the native loader   ##########"
Write-Host "##############################################################################"
Write-Host ""
Write-Host "  Every image in this half is Machine 0x8664 / Magic 0x020b (PE32+) -- verify"
Write-Host "  that in each cell's parsed header rather than taking it from this banner."
Write-Host "  These are native 64-bit images on an x64 runner: no WOW64 is involved."
Write-Host "  The i386 control above does NOT validate anything in this half.  A 32-bit"
Write-Host "  control only shows the harness reaches the WOW64 loader, which is exactly"
Write-Host "  the assumption this half exists not to make.  The x64 control below is the"
Write-Host "  only control on which these cells depend."
Write-Host ""
Write-Host "  The images in this half were built by the same tcc build, from the same"
Write-Host "  source, with the same flags as their i386 namesakes; the two halves differ"
Write-Host "  on the machine axis alone.  No result is anticipated here.  Agreement with"
Write-Host "  the i386 half is not expected and disagreement is not an error: either one"
Write-Host "  is the measurement this half was added to obtain."
Write-Host ""

Write-Host "########## x86-64 positive control ##########"
Write-Host ""
# The x64 half's own control, run first among the x64 cells.  If this one does
# not map as SEC_IMAGE and launch, the harness never reached the native 64-bit
# loader and every x64 number in this run is meaningless.
Cell "default-x64.exe" "x86-64: SectionAlignment 0x1000 / FileAlignment 0x200 -- ordinary alignment" 0x8664 0x020b ""
ControlBanner "default-x64.exe" "x86-64"
Write-Host ""

Write-Host "########## x86-64 sub-page SectionAlignment ##########"
Write-Host ""

Cell "subpage200-x64.exe" "x86-64: SectionAlignment == FileAlignment == 0x200, Subsystem 3" 0x8664 0x020b ""
Cell "subpage20-x64.exe"  "x86-64: SectionAlignment == FileAlignment == 0x20, Subsystem 3"  0x8664 0x020b ""
Cell "native20-x64.exe"   "x86-64: SectionAlignment == FileAlignment == 0x20, Subsystem 1 (native)" 0x8664 0x020b @"
this image declares Subsystem 1.  CreateProcessW does not create user-mode
      processes from native-subsystem images, so its CreateProcessW result is
      uninformative about alignment and must not be recorded as a finding on
      that axis.  Only the NtCreateSection(SEC_IMAGE) line above is on-axis for
      this cell.
"@

Write-Host "########## what the fork does, for contrast only ##########"
Write-Host ""
Write-Host "  The Wine fork at 89f964e69, run on the four i386 files, gives:"
Write-Host "      default.exe     -> runs, exit code 42"
Write-Host "      subpage200.exe  -> CreateProcess fails, ERROR_BAD_EXE_FORMAT"
Write-Host "      subpage20.exe   -> CreateProcess fails, ERROR_BAD_EXE_FORMAT"
Write-Host "  No fork run has been recorded for the four x86-64 files, so there is no"
Write-Host "  fork line to print for them and none is guessed at here."
Write-Host "  The above is WINE'S HYPOTHESIS ABOUT NT, NOT NT'S ANSWER.  It is printed here"
Write-Host "  only so a reader has the fork's behaviour to hand.  Whatever the cells"
Write-Host "  above report is the measurement; agreement with these lines is not"
Write-Host "  corroboration of anything, and disagreement is not an error in the probe."
Write-Host ""

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "done."
