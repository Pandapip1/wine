$ErrorActionPreference = "Stop"
Write-Output "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List

$cs = @"
using System; using System.Runtime.InteropServices;
public class P {
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

  public static string Std(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[24];
    int st = NtQueryInformationFile(h, io, b, 24, 5);
    long alloc = BitConverter.ToInt64(b,0), eof = BitConverter.ToInt64(b,8);
    return string.Format("EndOfFile={0,-9} Alloc={1,-9} (st=0x{2:x8})", eof, alloc, st);
  }

  // Returns the raw NTSTATUS, which DeviceIoControl's bool/GetLastError cannot express.
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
    IntPtr pout = Marshal.AllocHGlobal(sz * 64);
    uint ret = 0;
    bool ok = DeviceIoControl(h, FSCTL_QUERY_ALLOCATED_RANGES, pin, (uint)sz,
                              pout, (uint)(sz*64), out ret, IntPtr.Zero);
    string s = ok ? "" : ("query failed err=" + Marshal.GetLastWin32Error());
    if (ok) {
      int n = (int)(ret / sz);
      if (n == 0) s = "<no allocated extents: fully sparse>";
      for (int i = 0; i < n; i++) {
        long o = Marshal.ReadInt64(pout, i*sz);
        long b = Marshal.ReadInt64(pout, i*sz + 8);
        s += string.Format("[{0},{1}) ", o, o+b);
      }
    }
    Marshal.FreeHGlobal(pin); Marshal.FreeHGlobal(pout);
    return s;
  }
}
"@
Add-Type -TypeDefinition $cs

function NewFile([string]$tag, [bool]$sparse, [long]$size) {
  $p = Join-Path $env:TEMP "zde-$tag.bin"
  if (Test-Path $p) { Remove-Item $p -Force }
  $fs = [System.IO.File]::Open($p,'Create','ReadWrite','None')
  $h  = $fs.SafeFileHandle.DangerousGetHandle()
  if ($sparse) {
    $r = 0
    [void][P]::DeviceIoControl($h,[P]::FSCTL_SET_SPARSE,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$r,[IntPtr]::Zero)
  }
  if ($size -gt 0) {
    $chunk = New-Object byte[] 65536
    for ($i=0; $i -lt 65536; $i++) { $chunk[$i] = 0x78 }
    $left = $size
    while ($left -gt 0) {
      $n = [Math]::Min($left, 65536)
      $fs.Write($chunk,0,$n); $left -= $n
    }
    $fs.Flush($true)
  }
  return $fs
}

function Cell([string]$tag, [bool]$sparse, [long]$size, [long]$off, [long]$beyond, [string]$question) {
  Write-Output "=== [$tag] sparse-marked=$sparse size=$size  SET_ZERO_DATA($off, $beyond)"
  Write-Output "    QUESTION: $question"
  $fs = NewFile $tag $sparse $size
  $h = $fs.SafeFileHandle.DangerousGetHandle()
  Write-Output ("    before  {0}" -f [P]::Std($h))
  if ($size -gt 0) { Write-Output ("    before  extents: {0}" -f [P]::Ranges($h,$size)) }
  $st = [P]::ZeroData($h,$off,$beyond)
  Write-Output ("    NTSTATUS = 0x{0:x8}" -f $st)
  Write-Output ("    after   {0}" -f [P]::Std($h))
  if ($size -gt 0) { Write-Output ("    after   extents: {0}" -f [P]::Ranges($h,$size)) }
  $fs.Close(); Remove-Item $fs.Name -Force -ErrorAction SilentlyContinue
  Write-Output ""
}

# --- Granularity: at what unit does NTFS actually deallocate? ---
# The 64 KB/32 KB measurement showed no deallocation; the 1 MB/512 KB one did.
# The obvious reconciliation is a 64 KB sparse allocation unit, deallocated only
# when a whole unit is covered.  That is a HYPOTHESIS.  These cells discriminate
# it from a 4 KB-cluster rule and from a "size of file" rule.
Cell "gran-one-unit"   $true 1048576 65536  131072 "exactly one 64 KB-aligned unit: expect Alloc 1048576 -> 983040 if unit is 64 KB"
Cell "gran-one-cluster" $true 1048576 4096   8192   "one 4 KB cluster: any dealloc means granularity is finer than 64 KB"
Cell "gran-60k-aligned" $true 1048576 4096   65536  "60 KB ending on a unit boundary but not starting on one: dealloc => 4 KB rule"
Cell "gran-misaligned"  $true 1048576 32768  98304  "64 KB long but straddling two units: dealloc => alignment does not matter"
Cell "gran-partial-full-partial" $true 1048576 8192 122880 "covers NO whole 64 KB unit: expect no dealloc under the 64 KB rule"
Cell "gran-two-units"   $true 1048576 65536  196608 "two whole units: expect Alloc -> 917504"

# --- The refutation cells: does a LARGE, whole-range zero actually deallocate? ---
# The prior measurement used a 32 KB partial range in a 64 KB file. If NTFS simply
# declines to deallocate small runs, "never deallocates" is the wrong rule and a
# Wine implementation built on it would be wrong for every real caller.
Cell "big-sparse-whole"   $true  1048576 0       1048576 "1 MB sparse file, whole range: does Alloc drop to 0 / extents vanish?"
Cell "big-sparse-partial" $true  1048576 262144  786432  "1 MB sparse file, 512 KB aligned interior range: hole punched?"
Cell "big-nonsparse"      $false 1048576 262144  786432  "same range, NOT marked sparse: expected zero-in-place"

# --- Range vs EOF: may the FSCTL extend a file? ---
Cell "beyond-eof"    $true  4096 8192 16384 "range entirely past EOF: does the file grow, or is it a no-op?"
Cell "straddle-eof"  $true  4096 2048 16384 "range straddling EOF: is it clamped to EOF or does the file grow?"
Cell "at-eof"        $true  4096 4096 8192  "range starting exactly at EOF"

# --- Degenerate inputs: what NTSTATUS? ---
Cell "empty-range"   $true  4096 2048 2048  "Offset == Beyond: SUCCESS or INVALID_PARAMETER?"
Cell "inverted"      $true  4096 4096 2048  "Beyond < Offset: which NTSTATUS?"
Cell "negative-off"  $true  4096 -4096 2048 "negative FileOffset: which NTSTATUS?"
