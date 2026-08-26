$ErrorActionPreference = "Stop"
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List

# What does NT return when asked to execute a file that cannot hold an executable
# header?  Each cell writes a file with a .exe extension, then reports, raw:
#   - the length measured back from disk (not the length intended)
#   - the leading bytes in hex
#   - CreateProcessW's BOOL and GetLastError()
#   - the NTSTATUS from NtCreateSection(SEC_IMAGE) on a handle to that file
#   - the NTSTATUS from NtCreateSection(SEC_COMMIT) on the same file, as a
#     control on the axis: it says whether the file object itself can back a
#     section at all, independently of image parsing.
# No verdict is computed for any cell except the harness positive control.

$cs = @"
using System; using System.Runtime.InteropServices;
public class Q {
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

  // The raw NTSTATUS the Win32 BOOL/GetLastError pair cannot express.  This is
  // the call that maps the file as an image, the same operation a process
  // creation performs on the image file.
  public static string Section(string path, uint attrs, string label) {
    IntPtr h = CreateFileW(path, GENERIC_READ | GENERIC_EXECUTE, 1 | 2, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
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
}
"@
Add-Type -TypeDefinition $cs

$dir = Join-Path $env:TEMP "short-exe-probe"
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

# Emit one cell.  Everything printed here is a raw measurement.
function Cell([string]$tag, [byte[]]$bytes, [string]$what) {
  $p = Join-Path $dir "$tag.exe"
  [System.IO.File]::WriteAllBytes($p, $bytes)
  # Length measured back from disk: if the write came up short the cell is not
  # what it claims to be, and the reader must see that.
  $onDisk = [System.IO.File]::ReadAllBytes($p)
  Write-Host "=== [$tag] $what"
  Write-Host ("    intended length = {0}   length on disk = {1}" -f $bytes.Length, $onDisk.Length)
  if ($onDisk.Length -ne $bytes.Length) {
    Write-Host "    NOTE: short write -- this cell does not measure what its name says"
  }
  Write-Host ("    bytes: {0}" -f (HexHead $onDisk 24))
  Write-Host ("    {0}" -f [Q]::Launch($p))
  Write-Host ("    {0}" -f [Q]::Section($p, [Q]::SEC_IMAGE,  "NtCreateSection SEC_IMAGE "))
  Write-Host ("    {0}" -f [Q]::Section($p, [Q]::SEC_COMMIT, "NtCreateSection SEC_COMMIT"))
  Write-Host ""
}

function Junk([int]$n) {
  $b = New-Object byte[] $n
  for ($i = 0; $i -lt $n; $i++) { $b[$i] = [byte](0x41 + ($i % 26)) }
  return ,$b
}

# A 64-byte IMAGE_DOS_HEADER: e_magic at offset 0, e_lfanew (4 bytes) at 0x3c.
# Every other field is filler so that a parser cannot mistake it for zeroes.
function DosHeader([uint32]$lfanew) {
  $b = New-Object byte[] 64
  for ($i = 0; $i -lt 64; $i++) { $b[$i] = [byte](0x61 + ($i % 26)) }
  $b[0] = 0x4d; $b[1] = 0x5a          # 'M','Z' == 0x5a4d
  $le = [System.BitConverter]::GetBytes($lfanew)
  [System.Array]::Copy($le, 0, $b, 0x3c, 4)
  return ,$b
}

Write-Host "########## length sweep, no valid header ##########"
Write-Host ""
Cell "len-0"  (New-Object byte[] 0) "empty file"
Cell "len-1"  (Junk 1)  "1 byte, non-MZ"
Cell "len-2"  (Junk 2)  "2 bytes, non-MZ"
Cell "len-3"  (Junk 3)  "3 bytes, non-MZ"
Cell "len-63" (Junk 63) "63 bytes, non-MZ (one short of sizeof(IMAGE_DOS_HEADER))"
Cell "len-64" (Junk 64) "64 bytes, non-MZ (exactly sizeof(IMAGE_DOS_HEADER))"

Write-Host "########## valid MZ signature, truncated after it ##########"
Write-Host ""

$mz2 = New-Object byte[] 2
$mz2[0] = 0x4d; $mz2[1] = 0x5a
Cell "mz-2" $mz2 "2 bytes, exactly 'MZ' and nothing else"

Cell "mz-64-lfanew-past" (DosHeader 0x10000) "64-byte DOS header, e_lfanew = 0x10000 (past end of file)"
Cell "mz-64-lfanew-64"   (DosHeader 64)      "64-byte DOS header, e_lfanew = 64, file ends at 64"

# e_lfanew = 64, then a 2-byte fragment of the 4-byte PE signature.
$sigTrunc = (DosHeader 64) + [byte[]](0x50, 0x5a)
Cell "mz-pe-sig-trunc" $sigTrunc "66 bytes: DOS header + 2 of the 4 PE signature bytes"

# e_lfanew = 64, full "PE\0\0", then part of the 20-byte COFF file header.
$coffTrunc = (DosHeader 64) + [byte[]](0x50, 0x45, 0x00, 0x00) + (Junk 6)
Cell "mz-coff-trunc" $coffTrunc "74 bytes: DOS header + PE signature + 6 of 20 COFF header bytes"

# e_lfanew = 64, "PE\0\0", a complete 20-byte COFF header declaring a 0xE0-byte
# optional header, then only part of that optional header: total ~200 bytes.
$coff = New-Object byte[] 20
$m = [System.BitConverter]::GetBytes([uint16]0x8664); [System.Array]::Copy($m,0,$coff,0,2)   # Machine
$s = [System.BitConverter]::GetBytes([uint16]1);      [System.Array]::Copy($s,0,$coff,2,2)   # NumberOfSections
$o = [System.BitConverter]::GetBytes([uint16]0xE0);   [System.Array]::Copy($o,0,$coff,16,2)  # SizeOfOptionalHeader
$c = [System.BitConverter]::GetBytes([uint16]0x0022); [System.Array]::Copy($c,0,$coff,18,2)  # Characteristics
$optTrunc = (DosHeader 64) + [byte[]](0x50, 0x45, 0x00, 0x00) + $coff + (Junk 112)
Cell "mz-opt-trunc" $optTrunc "200 bytes: DOS header + PE signature + COFF header + 112 of 224 optional-header bytes"

Write-Host "########## complete headers, nonsense contents ##########"
Write-Host ""

# All declared structures present and fully sized; the values in them are junk.
$optFull = New-Object byte[] 224
for ($i = 0; $i -lt 224; $i++) { $optFull[$i] = [byte](0x30 + ($i % 10)) }
$om = [System.BitConverter]::GetBytes([uint16]0x020b); [System.Array]::Copy($om,0,$optFull,0,2)  # Magic PE32+
$nonsense = (DosHeader 64) + [byte[]](0x50, 0x45, 0x00, 0x00) + $coff + $optFull
Cell "mz-pe-nonsense" $nonsense "312 bytes: DOS header + PE signature + complete COFF + complete optional header, all values junk"

Write-Host "########## positive control ##########"
Write-Host ""
# A real, working image, copied into the same directory with the same .exe
# extension and exercised through exactly the same code paths as every cell
# above.  If this one does not launch, the harness is broken and every other
# number in this run is meaningless.
$real = Join-Path $dir "control-real.exe"
Copy-Item (Join-Path $env:SystemRoot "System32\cmd.exe") $real -Force
$realBytes = [System.IO.File]::ReadAllBytes($real)
Write-Host "=== [control-real] a genuine working image (copy of cmd.exe)"
Write-Host ("    length on disk = {0}" -f $realBytes.Length)
Write-Host ("    bytes: {0}" -f (HexHead $realBytes 24))
Write-Host ("    {0}" -f [Q]::Launch($real))
Write-Host ("    {0}" -f [Q]::Section($real, [Q]::SEC_IMAGE,  "NtCreateSection SEC_IMAGE "))
Write-Host ("    {0}" -f [Q]::Section($real, [Q]::SEC_COMMIT, "NtCreateSection SEC_COMMIT"))
$ctlOk = [Q]::LaunchOk($real)
if ($ctlOk) {
  Write-Host "    POSITIVE CONTROL PASS: a real image launches through this harness."
} else {
  Write-Host "    POSITIVE CONTROL FAIL: a real image does NOT launch through this harness."
  Write-Host "    THE HARNESS IS BROKEN AND THIS ENTIRE RUN IS VOID -- ignore every cell above."
}
Write-Host ""

Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "done."
