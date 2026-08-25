$ErrorActionPreference = "Stop"
Write-Output "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List

# What this probe settles
# -----------------------
# FSCTL_SET_ZERO_DATA takes a FILE_ZERO_DATA_INFORMATION, which is two LONGLONGs
# = 16 bytes.  What NT does when InputBufferLength is NOT 16 has never been
# measured here, so Wine's implementation currently guesses STATUS_INVALID_PARAMETER
# for a short buffer and says so.  The plausible answers differ:
#   STATUS_INVALID_PARAMETER   (0xc000000d)  - what the guess assumes
#   STATUS_INFO_LENGTH_MISMATCH(0xc0000004)  - the usual NT answer for a wrong-sized buffer
#   STATUS_BUFFER_TOO_SMALL    (0xc0000023)
#   STATUS_ACCESS_VIOLATION    (0xc0000005)  - for the NULL-pointer cells
#   STATUS_SUCCESS             (0x00000000)  - NT did not validate the length at all
# The bool from DeviceIoControl cannot distinguish these, so every cell reports the
# raw NTSTATUS from NtFsControlFile.
#
# Each cell also checks that the file did NOT change.  A short buffer that returns
# an error AND still zeroes data is the genuinely interesting outcome, and a
# status-only probe would miss it entirely.  The range used, [65536,131072), is the
# one measured to punch a real hole when the request is well-formed (run 32875115102,
# cell [gran-one-unit]: Alloc 1048576 -> 983040), so any honouring of a malformed
# request shows up loudly in the allocation size, the extent list, and the bytes.

$cs = @"
using System; using System.Runtime.InteropServices;
public class ZB {
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

  public static long AllocOf(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[24];
    NtQueryInformationFile(h, io, b, 24, 5);
    return BitConverter.ToInt64(b,0);
  }

  // Issue FSCTL_SET_ZERO_DATA with a caller-chosen InputBufferLength, independent of
  // how many bytes are actually allocated.  That separation is the whole point: it lets
  // us ask both "does NT reject a short declared length" and "does NT read past it".
  //   inLen    - the InputBufferLength passed to the kernel
  //   allocLen - bytes actually allocated (0 => pass a NULL pointer)
  // The first min(allocLen,16) bytes hold a well-formed FILE_ZERO_DATA_INFORMATION;
  // any surplus is zeroed.
  public static int ZeroDataRaw(IntPtr h, long off, long beyond, uint inLen, int allocLen) {
    IntPtr p = IntPtr.Zero;
    if (allocLen > 0) {
      p = Marshal.AllocHGlobal(allocLen);
      for (int i = 0; i < allocLen; i++) Marshal.WriteByte(p, i, 0);
      byte[] full = new byte[16];
      Buffer.BlockCopy(BitConverter.GetBytes(off),    0, full, 0, 8);
      Buffer.BlockCopy(BitConverter.GetBytes(beyond), 0, full, 8, 8);
      int n = Math.Min(allocLen, 16);
      for (int i = 0; i < n; i++) Marshal.WriteByte(p, i, full[i]);
    }
    byte[] io = new byte[16];
    int st;
    try {
      st = NtFsControlFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, io,
                           FSCTL_SET_ZERO_DATA, p, inLen, IntPtr.Zero, 0);
    } catch (Exception e) {
      // An access violation raised into managed code rather than returned as a status
      // is itself a result worth seeing, not a reason to abort the run.
      Console.WriteLine("    EXCEPTION: " + e.GetType().Name + ": " + e.Message);
      st = unchecked((int)0xdeadbeef);
    }
    if (p != IntPtr.Zero) Marshal.FreeHGlobal(p);
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

  // Confirm the bytes in [off,off+len) still hold the 0x78 fill.  The status alone
  // does not tell us whether data was touched.
  public static string DataIntact(System.IO.FileStream fs, long off, int len) {
    byte[] buf = new byte[len];
    long save = fs.Position;
    fs.Position = off;
    int got = 0;
    while (got < len) { int r = fs.Read(buf, got, len - got); if (r <= 0) break; got += r; }
    fs.Position = save;
    if (got != len) return "SHORT READ (" + got + " of " + len + ")";
    for (int i = 0; i < len; i++)
      if (buf[i] != 0x78)
        return string.Format("CHANGED: byte {0} is 0x{1:x2}, expected 0x78", off+i, buf[i]);
    return "intact (all 0x78)";
  }
}
"@
Add-Type -TypeDefinition $cs

function NewFile([string]$tag, [long]$size) {
  $p = Join-Path $env:TEMP "zdb-$tag.bin"
  if (Test-Path $p) { Remove-Item $p -Force }
  $fs = [System.IO.File]::Open($p,'Create','ReadWrite','None')
  $h  = $fs.SafeFileHandle.DangerousGetHandle()
  $r = 0
  [void][ZB]::DeviceIoControl($h,[ZB]::FSCTL_SET_SPARSE,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$r,[IntPtr]::Zero)
  $chunk = New-Object byte[] 65536
  for ($i=0; $i -lt 65536; $i++) { $chunk[$i] = 0x78 }
  $left = $size
  while ($left -gt 0) {
    $n = [Math]::Min($left, 65536)
    $fs.Write($chunk,0,$n); $left -= $n
  }
  $fs.Flush($true)
  return $fs
}

# Every cell asks for the SAME well-formed range, [65536,131072): one whole 64 KB
# aligned unit, measured to deallocate exactly 64 KB when the request is valid.
# Only the declared InputBufferLength and the allocation behind it vary, so the
# buffer length is the single axis under test.
$SIZE   = 1048576
$OFF    = 65536
$BEYOND = 131072

function Cell([string]$tag, [uint32]$inLen, [int]$allocLen, [string]$question) {
  $bufdesc = if ($allocLen -eq 0) { "NULL pointer" } else { "$allocLen bytes allocated" }
  Write-Output "=== [$tag] in_size=$inLen ($bufdesc)  SET_ZERO_DATA($OFF, $BEYOND)"
  Write-Output "    QUESTION: $question"
  $fs = NewFile $tag $SIZE
  $h = $fs.SafeFileHandle.DangerousGetHandle()
  $allocBefore = [ZB]::AllocOf($h)
  Write-Output ("    before  {0}" -f [ZB]::Std($h))
  Write-Output ("    before  extents: {0}" -f [ZB]::Ranges($h,$SIZE))
  $st = [ZB]::ZeroDataRaw($h,$OFF,$BEYOND,$inLen,$allocLen)
  Write-Output ("    NTSTATUS = 0x{0:x8}" -f $st)
  Write-Output ("    after   {0}" -f [ZB]::Std($h))
  Write-Output ("    after   extents: {0}" -f [ZB]::Ranges($h,$SIZE))
  Write-Output ("    data in target range: {0}" -f [ZB]::DataIntact($fs,$OFF,($BEYOND-$OFF)))
  $allocAfter = [ZB]::AllocOf($h)
  if ($allocAfter -ne $allocBefore) {
    Write-Output ("    >>> REQUEST WAS HONOURED: Alloc {0} -> {1} ({2} released)" -f `
                  $allocBefore, $allocAfter, ($allocBefore - $allocAfter))
  } else {
    Write-Output "    file unchanged"
  }
  $fs.Close(); Remove-Item $fs.Name -Force -ErrorAction SilentlyContinue
  Write-Output ""
}

# --- POSITIVE CONTROL -------------------------------------------------------
# Differs from every other cell on exactly the axis under test: this length is
# correct, all the others are not.  It MUST print NTSTATUS 0x00000000, "REQUEST WAS
# HONOURED ... 65536 released", and data CHANGED (zeroed).  If it does not, the
# harness is broken and no other cell in this file means anything -- an all-errors
# result would otherwise be indistinguishable from a probe that never reached NTFS.
Cell "ctl-exact-16" 16 16 "CONTROL: correct 16-byte buffer. MUST succeed and release 64 KB, or the run is void."

# --- NULL input buffer ------------------------------------------------------
Cell "null-len0"    0  0  "in_size=0 with a NULL buffer: INVALID_PARAMETER, INFO_LENGTH_MISMATCH or ACCESS_VIOLATION?"
Cell "null-len16"   16 0  "in_size=16 but the pointer is NULL: does NT fault, or reject before dereferencing?"

# --- Short declared length --------------------------------------------------
# Each short length is run twice: once with only that many bytes actually allocated,
# once with a full 16 behind the short declared length.  If the pair AGREES, the
# answer is a property of the declared length and is safe to encode in Wine.  If it
# DISAGREES, NT is reading past InputBufferLength -- which is itself the finding, and
# would mean the exact-allocation cell's status is the only trustworthy one.
Cell "short-8-alloc8"    8  8  "half the struct, only 8 bytes readable"
Cell "short-8-alloc16"   8  16 "half declared, 16 readable: same status as alloc8, or does NT read past in_size?"
Cell "short-15-alloc15"  15 15 "one byte short, only 15 readable"
Cell "short-15-alloc16"  15 16 "one byte short declared, 16 readable: pair with the above"
Cell "short-len0-buf"    0  16 "in_size=0 with a VALID non-NULL buffer: is it the length or the pointer NT objects to?"

# --- Surplus length ---------------------------------------------------------
# A real caller reaches this by passing sizeof() of a wrapper struct.  Tolerated or
# rejected is a live question: NT is inconsistent about surplus across FSCTLs.
Cell "long-24"      24 24 "24 bytes: is a surplus tolerated (SUCCESS + hole punched) or rejected?"
Cell "long-17"      17 17 "one byte over: pairs with the one-byte-short cell above"

Write-Output "=== INTERPRETATION ==="
Write-Output "If [ctl-exact-16] did not succeed and release 65536 bytes, disregard this entire run."
Write-Output "Otherwise, for each cell: the NTSTATUS is the answer for that in_size, and"
Write-Output "'file unchanged' + 'intact (all 0x78)' confirms a rejected request touched nothing."
Write-Output "Compare short-N-allocN against short-N-alloc16: agreement => the status depends on"
Write-Output "the declared length alone; disagreement => NT reads past InputBufferLength."
