$ErrorActionPreference = "Stop"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
Write-Host ("PowerShell process is 64-bit: {0}" -f [System.Environment]::Is64BitProcess)
Write-Host ""

# What does this kernel do with a PE whose SectionAlignment is smaller than the
# page size?  Four prebuilt images (see .github/probes/images/README) are
# exercised.  For each, raw:
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
  "subpage20.exe"  = "489368B986CA21AE98486A2A7989A5E1FC756A17C6B80FB34B90401D5122B863"
  "subpage200.exe" = "75C10877D50BBA918D3751701EF07457B789E1743433807AAF9EB18C438A9B5A"
  "native20.exe"   = "A3F7B535E1BFC753D920478035EDDC130C25FC1361321D5B6722A8E528CF1B2C"
  "default.exe"    = "B3B4817F4B8BF0688AF96A2652F026AD71C19ED8D2AC82DF38263F710D67AD0F"
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
  Write-Host ("    PE signature = 0x{0:x8}   Machine = 0x{1:x4}   NumberOfSections = {2}" -f $sig, $machine, $nsec)
  Write-Host ("    SizeOfOptionalHeader = 0x{0:x}   Characteristics = 0x{1:x4}   Magic = 0x{2:x4}" -f $sizeopt, $chars, $magic)
  Write-Host ("    SectionAlignment = 0x{0:x}   FileAlignment = 0x{1:x}" -f $sectAlign, $fileAlign)
  Write-Host ("    SizeOfImage = 0x{0:x}   Subsystem = {1} ({2})" -f $sizeImage, $subsys, (SubsystemName $subsys))
}

# Emit one cell.  Everything printed here is a raw measurement.
function Cell([string]$name, [string]$what, [string]$note) {
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
  Write-Host ("    {0}" -f [P]::Launch($p))
  Write-Host ("    {0}" -f [P]::Section($p, [P]::SEC_IMAGE,  "NtCreateSection SEC_IMAGE "))
  Write-Host ("    {0}" -f [P]::Section($p, [P]::SEC_COMMIT, "NtCreateSection SEC_COMMIT"))
  if ($note) { Write-Host ("    NOTE: {0}" -f $note) }
  Write-Host ""
}

Write-Host "########## positive control ##########"
Write-Host ""
# An image from the same toolchain and the same source, differing from the
# other cells only on the alignment axis under test.  If this one does not map
# as SEC_IMAGE and launch, the harness is broken and every other number in this
# run is meaningless.
Cell "default.exe" "SectionAlignment 0x1000 / FileAlignment 0x200 -- ordinary alignment" ""

$ctlLaunch  = [P]::LaunchOk((Join-Path $dir "default.exe"))
$ctlSection = [P]::SectionOk((Join-Path $dir "default.exe"), [P]::SEC_IMAGE)
if ($ctlLaunch -and $ctlSection) {
  Write-Host "    POSITIVE CONTROL PASS: an image from this toolchain maps as SEC_IMAGE and"
  Write-Host "    launches through this harness.  A different result on another cell is"
  Write-Host "    therefore about that cell, not about the harness."
} else {
  Write-Host ("    POSITIVE CONTROL FAIL: LaunchOk={0} SectionOk(SEC_IMAGE)={1}" -f $ctlLaunch, $ctlSection)
  Write-Host "    THE HARNESS IS BROKEN AND THIS ENTIRE RUN IS VOID -- ignore every cell below."
}
Write-Host ""

Write-Host "########## sub-page SectionAlignment ##########"
Write-Host ""

Cell "subpage200.exe" "SectionAlignment == FileAlignment == 0x200, Subsystem 3" ""
Cell "subpage20.exe"  "SectionAlignment == FileAlignment == 0x20, Subsystem 3"  ""
Cell "native20.exe"   "SectionAlignment == FileAlignment == 0x20, Subsystem 1 (native)" @"
this image declares Subsystem 1.  CreateProcessW does not create user-mode
      processes from native-subsystem images, so its CreateProcessW result is
      uninformative about alignment and must not be recorded as a finding on
      that axis.  Only the NtCreateSection(SEC_IMAGE) line above is on-axis for
      this cell.
"@

Write-Host "########## what the fork does, for contrast only ##########"
Write-Host ""
Write-Host "  The Wine fork at 89f964e69, run on these same four files, gives:"
Write-Host "      default.exe     -> runs, exit code 42"
Write-Host "      subpage200.exe  -> CreateProcess fails, ERROR_BAD_EXE_FORMAT"
Write-Host "      subpage20.exe   -> CreateProcess fails, ERROR_BAD_EXE_FORMAT"
Write-Host "  That is WINE'S HYPOTHESIS ABOUT NT, NOT NT'S ANSWER.  It is printed here"
Write-Host "  only so a reader has the fork's behaviour to hand.  Whatever the cells"
Write-Host "  above report is the measurement; agreement with these lines is not"
Write-Host "  corroboration of anything, and disagreement is not an error in the probe."
Write-Host ""

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "done."
