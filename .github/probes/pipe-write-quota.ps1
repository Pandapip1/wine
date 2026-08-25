$ErrorActionPreference = "Stop"
Write-Output "OS: $([System.Environment]::OSVersion.VersionString)"
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber | Format-List
Write-Output "IntPtr.Size = $([IntPtr]::Size)  (this probe hard-codes x64 OBJECT_ATTRIBUTES offsets)"
Write-Output ""
Write-Output "########################################################################"
Write-Output "# QUESTION: on real NT, does FILE_PIPE_LOCAL_INFORMATION.WriteQuotaAvailable"
Write-Output "#           track the actual free space in the pipe buffer, or is it inert?"
Write-Output "#"
Write-Output "# This script prints RAW field values only. It computes no verdict and"
Write-Output "# prints no PASS/FAIL, EXCEPT for the positive control below."
Write-Output "#"
Write-Output "# HANDLE SETUP, identical in every cell:"
Write-Output "#   SERVER handle = NtCreateNamedPipeFile(\??\pipe\<name>), MaximumInstances=1."
Write-Output "#   CLIENT handle = CreateFileW(\\.\pipe\<name>), GENERIC_READ|GENERIC_WRITE."
Write-Output "#   All data is written on the SERVER handle, so it lands in the SERVER's"
Write-Output "#   OUTBOUND buffer and is readable on the CLIENT handle."
Write-Output "#   Therefore, if the field is live, the cell expects it to move on the"
Write-Output "#   SERVER's WriteQuotaAvailable and on the CLIENT's ReadDataAvailable."
Write-Output "#   BOTH ends are queried in every cell. All ten ULONGs are printed raw."
Write-Output "#"
Write-Output "# ANTI-HANG: the server handle is created with CompletionMode ="
Write-Output "#   FILE_PIPE_COMPLETE_OPERATION (non-blocking) in every cell except the"
Write-Output "#   two mode cells at the end, which are bounded to half the quota. Writes"
Write-Output "#   are looped and stop as soon as a write moves zero bytes, so a full"
Write-Output "#   pipe cannot block the run. Reads only ever ask for bytes we already"
Write-Output "#   know are buffered."
Write-Output "########################################################################"
Write-Output ""

$cs = @"
using System; using System.Runtime.InteropServices;
public class P {
  [DllImport("ntdll.dll")]
  public static extern int NtQueryInformationFile(IntPtr h, byte[] iosb, byte[] inf, uint len, int cls);
  [DllImport("ntdll.dll")]
  public static extern int NtCreateNamedPipeFile(out IntPtr h, uint access, IntPtr oa, byte[] iosb,
    uint share, uint disp, uint opts, uint type, uint readMode, uint compMode,
    uint maxInst, uint inQ, uint outQ, IntPtr timeout);
  [DllImport("ntdll.dll")]
  public static extern int NtWriteFile(IntPtr h, IntPtr ev, IntPtr apc, IntPtr ctx, byte[] iosb,
    IntPtr buf, uint len, IntPtr off, IntPtr key);
  [DllImport("ntdll.dll")]
  public static extern int NtReadFile(IntPtr h, IntPtr ev, IntPtr apc, IntPtr ctx, byte[] iosb,
    IntPtr buf, uint len, IntPtr off, IntPtr key);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sa,
    uint disp, uint flags, IntPtr tmpl);
  [DllImport("kernel32.dll", SetLastError=true)]
  public static extern bool CloseHandle(IntPtr h);

  public const int  FilePipeLocalInformation = 24;   // the info class under test
  public const int  FileStandardInformation  = 5;
  public const uint FILE_CREATE                    = 2;
  public const uint FILE_SYNCHRONOUS_IO_NONALERT   = 0x00000020;
  public const uint FILE_PIPE_BYTE_STREAM_TYPE     = 0;
  public const uint FILE_PIPE_MESSAGE_TYPE         = 1;
  public const uint FILE_PIPE_BYTE_STREAM_MODE     = 0;
  public const uint FILE_PIPE_MESSAGE_MODE         = 1;
  public const uint FILE_PIPE_QUEUE_OPERATION      = 0;  // blocking
  public const uint FILE_PIPE_COMPLETE_OPERATION   = 1;  // non-blocking
  public static IntPtr INVALID = new IntPtr(-1);

  static IntPtr sBuf = IntPtr.Zero;
  static int    sBufLen = 0;
  static IntPtr Buf(int n) {
    if (n > sBufLen) {
      if (sBuf != IntPtr.Zero) Marshal.FreeHGlobal(sBuf);
      sBuf = Marshal.AllocHGlobal(n); sBufLen = n;
    }
    return sBuf;
  }

  // last NtWriteFile / NtReadFile aggregate, so the caller can drain exactly what it filled
  public static int LastMoved = 0;

  static IntPtr BuildObjA(string ntpath) {
    IntPtr nameBuf = Marshal.StringToHGlobalUni(ntpath);
    IntPtr us = Marshal.AllocHGlobal(16);
    Marshal.WriteInt16(us, 0, (short)(ntpath.Length * 2));
    Marshal.WriteInt16(us, 2, (short)(ntpath.Length * 2 + 2));
    Marshal.WriteInt32(us, 4, 0);
    Marshal.WriteIntPtr(us, 8, nameBuf);
    IntPtr oa = Marshal.AllocHGlobal(48);
    for (int i = 0; i < 48; i++) Marshal.WriteByte(oa, i, 0);
    Marshal.WriteInt32(oa, 0, 48);      // Length
    Marshal.WriteIntPtr(oa, 16, us);    // ObjectName
    Marshal.WriteInt32(oa, 24, 0x40);   // Attributes = OBJ_CASE_INSENSITIVE
    return oa;
  }

  public static int CreateServer(string ntpath, uint inQ, uint outQ,
                                 uint type, uint readMode, uint compMode, out IntPtr h) {
    h = IntPtr.Zero;
    IntPtr oa = BuildObjA(ntpath);
    IntPtr to = Marshal.AllocHGlobal(8);
    Marshal.WriteInt64(to, -500000L);   // 50 ms relative default timeout
    byte[] io = new byte[16];
    uint access = 0x40000000u | 0x80000000u | 0x00100000u;  // GENERIC_WRITE|GENERIC_READ|SYNCHRONIZE
    int st = NtCreateNamedPipeFile(out h, access, oa, io,
               3 /* FILE_SHARE_READ|WRITE */, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT,
               type, readMode, compMode, 1 /* MaximumInstances */, inQ, outQ, to);
    Marshal.FreeHGlobal(to);
    return st;
  }

  public static IntPtr OpenClient(string dosname) {
    return CreateFileW(dosname, 0x80000000u | 0x40000000u, 0, IntPtr.Zero,
                       3 /* OPEN_EXISTING */, 0, IntPtr.Zero);
  }

  // Raw FILE_PIPE_LOCAL_INFORMATION: 10 ULONGs, 40 bytes. Every one is printed.
  public static string Local(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[40];
    int st = NtQueryInformationFile(h, io, b, 40, FilePipeLocalInformation);
    if (st != 0)
      return string.Format("NtQueryInformationFile(FilePipeLocalInformation) NTSTATUS=0x{0:x8}  <no data>", st);
    uint[] f = new uint[10];
    for (int i = 0; i < 10; i++) f[i] = BitConverter.ToUInt32(b, i * 4);
    return string.Format(
      "st=0x{0:x8} Type={1} Config={2} MaxInst={3} CurInst={4} InboundQuota={5} ReadDataAvailable={6} OutboundQuota={7} WriteQuotaAvailable={8} State={9} End={10}",
      st, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9]);
  }

  // Raw WriteQuotaAvailable / ReadDataAvailable for programmatic use by the control cell.
  public static long Field(IntPtr h, int idx) {
    byte[] io = new byte[16]; byte[] b = new byte[40];
    int st = NtQueryInformationFile(h, io, b, 40, FilePipeLocalInformation);
    if (st != 0) return -1;
    return (long)BitConverter.ToUInt32(b, idx * 4);
  }

  // Lifted from zero-data-edges.ps1; printed for both ends as extra raw context.
  public static string Std(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[24];
    int st = NtQueryInformationFile(h, io, b, 24, FileStandardInformation);
    long alloc = BitConverter.ToInt64(b,0), eof = BitConverter.ToInt64(b,8);
    return string.Format("EndOfFile={0,-9} Alloc={1,-9} (st=0x{2:x8})", eof, alloc, st);
  }

  // Bounded, loop-driven write. Stops the instant a write moves zero bytes, so a
  // full pipe can never hang the run even on a blocking handle.
  public static string Fill(IntPtr h, int total) {
    IntPtr p = Buf(total > 0 ? total : 1);
    int done = 0, laststatus = 0, iters = 0;
    while (done < total && iters < 4096) {
      iters++;
      byte[] io = new byte[16];
      int chunk = total - done;
      laststatus = NtWriteFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, io,
                               new IntPtr(p.ToInt64() + done), (uint)chunk, IntPtr.Zero, IntPtr.Zero);
      int moved = (int)BitConverter.ToInt64(io, 8);
      if (laststatus != 0 || moved <= 0) { done += (laststatus == 0 ? moved : 0); break; }
      done += moved;
    }
    LastMoved = done;
    return string.Format("write requested={0} written={1} last-NTSTATUS=0x{2:x8} iters={3}", total, done, laststatus, iters);
  }

  public static string Drain(IntPtr h, int total) {
    IntPtr p = Buf(total > 0 ? total : 1);
    int done = 0, laststatus = 0, iters = 0;
    while (done < total && iters < 4096) {
      iters++;
      byte[] io = new byte[16];
      int chunk = total - done;
      laststatus = NtReadFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, io,
                              new IntPtr(p.ToInt64() + done), (uint)chunk, IntPtr.Zero, IntPtr.Zero);
      int moved = (int)BitConverter.ToInt64(io, 8);
      if (laststatus != 0 || moved <= 0) { done += (laststatus == 0 ? moved : 0); break; }
      done += moved;
    }
    LastMoved = done;
    return string.Format("read requested={0} read={1} last-NTSTATUS=0x{2:x8} iters={3}", total, done, laststatus, iters);
  }

  // ------------------------------------------------------------------
  // N discrete writes of S bytes each. Used by the message-overhead cells.
  //
  // Unlike Fill(), this does NOT coalesce: it issues EXACTLY one NtWriteFile
  // per message, because on a message-type pipe one NtWriteFile == one message
  // and the whole point of these cells is the message COUNT.
  //
  // ANTI-HANG: the loop runs at most N times (N is a small literal at every
  // call site) and breaks out immediately on any non-zero NTSTATUS or any
  // short write. Callers keep N*S far below the quota, and the handle is
  // created non-blocking, so a write can never wait on a full buffer.
  public static int LastCount = 0;
  public static string WriteN(IntPtr h, int n, int s) {
    IntPtr p = Buf(s > 0 ? s : 1);
    for (int i = 0; i < s; i++) Marshal.WriteByte(p, i, (byte)(i & 0xff));
    int ok = 0, bytes = 0, laststatus = 0, badIndex = -1, badStatus = 0, badMoved = -1;
    for (int i = 0; i < n; i++) {
      byte[] io = new byte[16];
      laststatus = NtWriteFile(h, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, io,
                               p, (uint)s, IntPtr.Zero, IntPtr.Zero);
      int moved = (int)BitConverter.ToInt64(io, 8);
      if (laststatus != 0) { badIndex = i; badStatus = laststatus; badMoved = moved; break; }
      bytes += moved;
      if (moved != s) { badIndex = i; badStatus = laststatus; badMoved = moved; break; }
      ok++;
    }
    LastMoved = bytes; LastCount = ok;
    return string.Format(
      "writes: requested N={0} of S={1} (N*S={2})  completed-writes={3}  bytes-written={4}  first-bad-write-index={5} (its NTSTATUS=0x{6:x8}, bytes-moved={7})  last-NTSTATUS=0x{8:x8}",
      n, s, (long)n * s, ok, bytes, badIndex, badStatus, badMoved, laststatus);
  }
}
"@
Add-Type -TypeDefinition $cs

$script:seq = 0
function NewNames {
  $script:seq++
  $n = "wqp-$PID-$($script:seq)"
  return @{ Nt = "\??\pipe\$n"; Dos = "\\.\pipe\$n"; Short = $n }
}

# ---------------------------------------------------------------------------
# One cell = one pipe, created fresh, driven into EXACTLY ONE fill state,
# then queried on both ends. Quota and fill state are never varied together
# within a cell; each cell differs from its siblings on one axis only.
# ---------------------------------------------------------------------------
function Cell {
  param(
    [string]$Tag,
    [uint32]$ReqQuota,
    [string]$FillState,      # fresh | half | full | full-drained | full-half-drained
    [uint32]$PipeType  = 0,  # FILE_PIPE_BYTE_STREAM_TYPE
    [uint32]$ReadMode  = 0,  # FILE_PIPE_BYTE_STREAM_MODE
    [uint32]$CompMode  = 1,  # FILE_PIPE_COMPLETE_OPERATION (non-blocking)
    [string]$Reader    = "open-idle",   # open-idle | closed
    [string]$Note      = ""
  )
  $modeStr = "type=$PipeType readmode=$ReadMode compmode=$CompMode(" + $(if ($CompMode -eq 1) { "non-blocking" } else { "blocking" }) + ")"
  Write-Output "=== [$Tag] requested-quota=$ReqQuota fill=$FillState reader=$Reader $modeStr"
  if ($Note) { Write-Output "    NOTE: $Note" }

  $nm = NewNames
  $sh = [IntPtr]::Zero
  $st = [P]::CreateServer($nm.Nt, $ReqQuota, $ReqQuota, $PipeType, $ReadMode, $CompMode, [ref]$sh)
  Write-Output ("    NtCreateNamedPipeFile(InboundQuota={0}, OutboundQuota={1}) NTSTATUS=0x{2:x8}" -f $ReqQuota, $ReqQuota, $st)
  if ($st -ne 0) {
    Write-Output "    pipe not created; that NTSTATUS is the result for this cell."
    Write-Output ""
    return
  }

  # Requested vs reported quota, BEFORE anything else touches the pipe.
  # If NT rounds or ignores the request, cells labelled 4096 and 65536 may be
  # the same stimulus; this line is what makes that visible.
  Write-Output ("    server fresh   {0}" -f [P]::Local($sh))
  $effOut = [P]::Field($sh, 6)   # OutboundQuota as REPORTED, used for all fill arithmetic
  Write-Output ("    effective OutboundQuota as reported by NT = {0} (requested {1}); all fill amounts below derive from the REPORTED value" -f $effOut, $ReqQuota)

  $ch = [P]::OpenClient($nm.Dos)
  if ($ch -eq [P]::INVALID) {
    Write-Output ("    CreateFileW({0}) FAILED err={1}" -f $nm.Dos, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    [void][P]::CloseHandle($sh); Write-Output ""; return
  }
  Write-Output ("    client connected: {0}" -f $nm.Dos)

  if ($effOut -le 0) {
    Write-Output "    reported OutboundQuota is $effOut; fill arithmetic is not meaningful, reporting connected state only."
    $FillState = "fresh"
  }

  switch ($FillState) {
    "fresh" { }
    "half"  { Write-Output ("    {0}" -f [P]::Fill($sh, [int]($effOut / 2))) }
    "full"  { Write-Output ("    {0}" -f [P]::Fill($sh, [int]$effOut)) }
    "full-drained" {
      Write-Output ("    {0}" -f [P]::Fill($sh, [int]$effOut))
      $w = [P]::LastMoved
      Write-Output ("    {0}" -f [P]::Drain($ch, $w))
    }
    "full-half-drained" {
      Write-Output ("    {0}" -f [P]::Fill($sh, [int]$effOut))
      $w = [P]::LastMoved
      Write-Output ("    {0}" -f [P]::Drain($ch, [int]($w / 2)))
    }
    default { Write-Output "    UNKNOWN FILL STATE '$FillState' - cell not driven" }
  }

  if ($Reader -eq "closed") {
    [void][P]::CloseHandle($ch)
    $ch = [P]::INVALID
    Write-Output "    client handle CLOSED before the queries below"
  }

  Write-Output ("    SERVER (writing end)  {0}" -f [P]::Local($sh))
  Write-Output ("    SERVER  std           {0}" -f [P]::Std($sh))
  if ($ch -ne [P]::INVALID) {
    Write-Output ("    CLIENT (reading end)  {0}" -f [P]::Local($ch))
    Write-Output ("    CLIENT  std           {0}" -f [P]::Std($ch))
    [void][P]::CloseHandle($ch)
  } else {
    Write-Output "    CLIENT (reading end)  <handle closed; not queried>"
  }
  [void][P]::CloseHandle($sh)
  Write-Output ""
}

# ===========================================================================
# POSITIVE CONTROL - MUST BEHAVE.
#
# If every cell below reports WriteQuotaAvailable = 0, that is equally
# consistent with "the field is inert on NT" and "this harness never built a
# working pipe / the query never reached a pipe". This cell discriminates
# those two, using a DIFFERENT field of the SAME 40-byte structure returned by
# the SAME NtQueryInformationFile call:
#
#   write exactly 1000 bytes on the server handle, then assert that the
#   CLIENT end reports ReadDataAvailable == 1000.
#
# Passing proves: the pipe was created, the client connected, the bytes really
# entered the buffer, and FilePipeLocalInformation really reached this pipe and
# returned live per-pipe state. It therefore proves that a WriteQuotaAvailable
# of 0 elsewhere is a fact about the field, not about the harness.
#
# IF THIS CONTROL FAILS, THE ENTIRE RUN IS VOID - every other cell below must
# be discarded, and no conclusion of any kind may be drawn from this run.
# ===========================================================================
Write-Output "=== [CONTROL] positive control - if this fails the ENTIRE RUN IS VOID"
$nm = NewNames
$sh = [IntPtr]::Zero
$st = [P]::CreateServer($nm.Nt, 65536, 65536, 0, 0, 1, [ref]$sh)
Write-Output ("    NtCreateNamedPipeFile NTSTATUS=0x{0:x8}" -f $st)
$controlOk = $false
if ($st -eq 0) {
  $ch = [P]::OpenClient($nm.Dos)
  if ($ch -ne [P]::INVALID) {
    Write-Output ("    {0}" -f [P]::Fill($sh, 1000))
    $wrote = [P]::LastMoved
    Write-Output ("    SERVER  {0}" -f [P]::Local($sh))
    Write-Output ("    CLIENT  {0}" -f [P]::Local($ch))
    $rda = [P]::Field($ch, 5)   # ReadDataAvailable on the client (reading) end
    Write-Output ("    assertion: wrote={0}  client ReadDataAvailable={1}" -f $wrote, $rda)
    if ($wrote -eq 1000 -and $rda -eq 1000) { $controlOk = $true }
    [void][P]::CloseHandle($ch)
  } else {
    Write-Output ("    CreateFileW FAILED err={0}" -f [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  }
  [void][P]::CloseHandle($sh)
}
if ($controlOk) {
  Write-Output "    CONTROL OK: the pipe works and FilePipeLocalInformation returns live per-pipe state."
  Write-Output "                A WriteQuotaAvailable of 0 below is therefore a fact about the field."
} else {
  Write-Output "    *** CONTROL FAILED ***"
  Write-Output "    *** THE ENTIRE RUN IS VOID. Discard every cell below. No conclusion may be"
  Write-Output "    *** drawn about WriteQuotaAvailable from this run."
}
Write-Output ""

# ===========================================================================
# AXIS 1: quota x fill state.
# Five fill states per quota. Within a row only the fill state changes;
# between rows only the requested quota changes.
# ===========================================================================
Write-Output "########## AXIS 1: requested quota x fill state ##########"
Write-Output ""

foreach ($q in 65536, 4096, 1048576, 0) {
  $label = if ($q -eq 0) { "0 (ask NT for its system default; if the create is rejected, that NTSTATUS is the result)" } else { "$q" }
  Write-Output "---------- requested quota = $label ----------"
  Cell -Tag "q$q-a-fresh"        -ReqQuota $q -FillState "fresh"             -Note "(a) freshly created, nothing written"
  Cell -Tag "q$q-b-half"         -ReqQuota $q -FillState "half"              -Note "(b) half the reported outbound quota written, no reader draining"
  Cell -Tag "q$q-c-full"         -ReqQuota $q -FillState "full"              -Note "(c) filled to the reported outbound quota, no reader draining"
  Cell -Tag "q$q-d-drained"      -ReqQuota $q -FillState "full-drained"      -Note "(d) filled, then fully drained by the client"
  Cell -Tag "q$q-e-half-drained" -ReqQuota $q -FillState "full-half-drained" -Note "(e) filled, then half drained by the client"
}

# ===========================================================================
# AXIS 2: reader disposition, at the default quota only.
# Fill state is held FIXED at half so that a live WriteQuotaAvailable would be
# non-zero and non-full in all three cells; only the reader's disposition
# varies. The 'closed' cell reports what the field reads, and what NTSTATUS
# the query itself returns, before any I/O would discover the broken pipe.
# ===========================================================================
Write-Output "########## AXIS 2: reader disposition at the default quota (fill held at half) ##########"
Write-Output ""
Cell -Tag "rd-open-idle" -ReqQuota 65536 -FillState "half" -Reader "open-idle" `
     -Note "read end open, never reads"
Cell -Tag "rd-draining"  -ReqQuota 65536 -FillState "full-half-drained" -Reader "open-idle" `
     -Note "read end actively draining. NOTE: this cell necessarily differs from rd-open-idle in fill history as well as reader behaviour - 'a reader that drains' is not expressible without changing what is in the buffer. Compare it to q65536-e-half-drained, which is the same stimulus."
Cell -Tag "rd-closed"    -ReqQuota 65536 -FillState "half" -Reader "closed" `
     -Note "read end CLOSED before the query. Same fill as rd-open-idle; only the reader disposition differs. The server-side NTSTATUS printed below is the query's own status."

# ===========================================================================
# AXIS 3: pipe mode, at the default quota only. Lowest priority; included
# because it costs one extra pipe per cell. Fill held at half so a blocking
# handle cannot block (half a quota always fits in an empty buffer).
# ===========================================================================
Write-Output "########## AXIS 3: pipe mode at the default quota (fill held at half) ##########"
Write-Output ""
Cell -Tag "mode-byte-nonblocking" -ReqQuota 65536 -FillState "half" -PipeType 0 -ReadMode 0 -CompMode 1 `
     -Note "byte type, byte read mode, FILE_PIPE_COMPLETE_OPERATION (this is the mode used by every cell above)"
Cell -Tag "mode-byte-blocking"    -ReqQuota 65536 -FillState "half" -PipeType 0 -ReadMode 0 -CompMode 0 `
     -Note "byte type, byte read mode, FILE_PIPE_QUEUE_OPERATION (blocking). Only CompletionMode differs from mode-byte-nonblocking."
Cell -Tag "mode-msg-nonblocking"  -ReqQuota 65536 -FillState "half" -PipeType 1 -ReadMode 1 -CompMode 1 `
     -Note "message type, message read mode, non-blocking. Only the type/read-mode differs from mode-byte-nonblocking."
Cell -Tag "mode-msg-blocking"     -ReqQuota 65536 -FillState "half" -PipeType 1 -ReadMode 1 -CompMode 0 `
     -Note "message type, message read mode, blocking."

# ===========================================================================
# AXIS 4: does WriteQuotaAvailable subtract DATA BYTES, or BUFFER SPACE
#         CONSUMED (which on a message pipe may include per-message
#         bookkeeping charged against the quota)?
#
# Run 32877718116 established that WriteQuotaAvailable is live: an end's value
# is its write-direction quota minus what is buffered in that direction. Every
# cell in that run wrote byte-stream data with no per-message framing, so it
# could not separate:
#
#   (H1) NT subtracts exactly the number of DATA BYTES buffered.
#   (H2) NT subtracts the buffer space CONSUMED, message bookkeeping included.
#
# The existing mode-msg-* cells wrote ONE 32768-byte message and reported
# 32768. One message carries one message's worth of overhead, which could be
# zero, rounded away, or simply not charged - so those cells do not separate
# H1 from H2 either.
#
# DISCRIMINATOR: MANY SMALL MESSAGES vs THE SAME TOTAL IN BYTE MODE.
# Every cell below writes N*S = 16384 bytes at the same requested quota
# (65536, the default, so these are comparable with the AXIS 1-3 cells), but
# splits that total across a different number of writes. Each message-mode
# shape is paired with a BYTE-MODE CONTROL that writes the identical total in
# the identical chunk sizes. The byte-mode control is what makes the
# message-mode number interpretable: any per-message charge is the DIFFERENCE
# between the pair, so neither number has to be read on its own, and any
# effect of merely issuing many small writes (as opposed to many MESSAGES)
# shows up in the byte-mode member of the pair.
#
# N is varied at a constant total so a PER-MESSAGE cost separates from a
# FIXED cost: if the deficit tracks N and not N*S, it is per-message.
#
# NO VERDICT IS COMPUTED HERE. Each cell prints the raw ten fields for both
# ends, the requested and the effective quota, N, S, N*S, the raw NTSTATUS
# values, the arithmetic value (effective-quota - N*S) next to the observed
# WriteQuotaAvailable, their difference, and that difference divided by N.
# Which hypothesis those numbers support is the reader's call.
#
# ANTI-HANG: every cell writes 16384 bytes into a >= 65536-byte quota, the
# server handle is non-blocking (FILE_PIPE_COMPLETE_OPERATION), every write
# loop is bounded by the literal N, and the loop breaks on the first non-zero
# NTSTATUS or short write. Nothing is ever read back, so no read can wait on
# an empty buffer either.
#
# PER-CELL POSITIVE CONTROL: if message-mode writes silently failed, the
# deficit would be zero and would read as H1. So each cell asserts that the
# CLIENT end's ReadDataAvailable equals the N*S it believes it wrote, and
# prints both numbers whether or not they agree. A cell whose control line
# says MISMATCH carries no information about the quota arithmetic.
# ===========================================================================
Write-Output "########## AXIS 4: message-count vs byte-total, at the default quota ##########"
Write-Output ""

function MsgCell {
  param(
    [string]$Tag,
    [uint32]$ReqQuota,
    [int]$N,
    [int]$S,
    [uint32]$PipeType,      # 0 = FILE_PIPE_BYTE_STREAM_TYPE, 1 = FILE_PIPE_MESSAGE_TYPE
    [uint32]$ReadMode,      # 0 = FILE_PIPE_BYTE_STREAM_MODE, 1 = FILE_PIPE_MESSAGE_MODE
    [string]$Note = ""
  )
  # Write-Host, not Write-Output: output written inside a function is captured
  # by an assignment at the call site instead of being printed. That bug has
  # already been caught twice in these scripts and the AST parser does not see
  # it, so this function never uses Write-Output.
  $total = $N * $S
  $typeStr = $(if ($PipeType -eq 1) { "MESSAGE" } else { "BYTE-STREAM" })
  Write-Host "=== [$Tag] requested-quota=$ReqQuota N=$N S=$S N*S=$total type=$PipeType($typeStr) readmode=$ReadMode compmode=1(non-blocking)"
  if ($Note) { Write-Host "    NOTE: $Note" }

  $nm = NewNames
  $sh = [IntPtr]::Zero
  $st = [P]::CreateServer($nm.Nt, $ReqQuota, $ReqQuota, $PipeType, $ReadMode, 1, [ref]$sh)
  Write-Host ("    NtCreateNamedPipeFile(InboundQuota={0}, OutboundQuota={1}) NTSTATUS=0x{2:x8}" -f $ReqQuota, $ReqQuota, $st)
  if ($st -ne 0) {
    Write-Host "    pipe not created; that NTSTATUS is the result for this cell."
    Write-Host ""
    return
  }

  Write-Host ("    server fresh          {0}" -f [P]::Local($sh))
  $effIn  = [P]::Field($sh, 4)   # InboundQuota  as reported by NT
  $effOut = [P]::Field($sh, 6)   # OutboundQuota as reported by NT
  Write-Host ("    effective quotas as reported by NT: InboundQuota={0} OutboundQuota={1} (both requested as {2})" -f $effIn, $effOut, $ReqQuota)
  if ($effOut -ne [long]$ReqQuota) {
    Write-Host "    WARNING: NT did not report back the requested outbound quota. This cell is NOT directly comparable with cells whose effective quota differs."
  }
  if ($effOut -gt 0 -and $total -ge $effOut) {
    Write-Host "    REFUSING TO WRITE: N*S is not below the effective outbound quota; writing could fill the pipe. Cell skipped."
    [void][P]::CloseHandle($sh); Write-Host ""; return
  }

  $ch = [P]::OpenClient($nm.Dos)
  if ($ch -eq [P]::INVALID) {
    Write-Host ("    CreateFileW({0}) FAILED err={1}" -f $nm.Dos, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
    [void][P]::CloseHandle($sh); Write-Host ""; return
  }
  Write-Host ("    client connected: {0}" -f $nm.Dos)

  Write-Host ("    {0}" -f [P]::WriteN($sh, $N, $S))
  $wrote  = [P]::LastMoved
  $nDone  = [P]::LastCount

  Write-Host ("    SERVER (writing end)  {0}" -f [P]::Local($sh))
  Write-Host ("    SERVER  std           {0}" -f [P]::Std($sh))
  Write-Host ("    CLIENT (reading end)  {0}" -f [P]::Local($ch))
  Write-Host ("    CLIENT  std           {0}" -f [P]::Std($ch))

  # Per-cell positive control: the bytes must actually be in the buffer.
  $rda = [P]::Field($ch, 5)      # ReadDataAvailable on the client (reading) end
  $ctl = $(if ($wrote -eq $total -and $nDone -eq $N -and $rda -eq [long]$total) { "OK" } else { "MISMATCH" })
  Write-Host ("    CONTROL [{0}]: intended N*S={1}  bytes-actually-written={2}  writes-completed={3}/{4}  client ReadDataAvailable={5}" -f $ctl, $total, $wrote, $nDone, $N, $rda)
  if ($ctl -ne "OK") {
    Write-Host "    CONTROL MISMATCH: the writes did not all land as intended. The quota arithmetic printed below says nothing about message overhead for this cell."
  }

  # Arithmetic, printed so a reader does not have to compute it. Not a verdict.
  $wqa = [P]::Field($sh, 7)      # WriteQuotaAvailable on the server (writing) end
  $expected = [long]$effOut - [long]$total
  $diff = $expected - $wqa
  Write-Host ("    ARITHMETIC: effective-OutboundQuota({0}) - N*S({1}) = {2}   observed server WriteQuotaAvailable = {3}   difference = {4}" -f $effOut, $total, $expected, $wqa, $diff)
  if ($N -gt 0) {
    Write-Host ("    ARITHMETIC: difference / N = {0} / {1} = {2}" -f $diff, $N, ([double]$diff / [double]$N))
  }
  Write-Host ("    ARITHMETIC: bytes-actually-written = {0}; effective-OutboundQuota - bytes-actually-written = {1}" -f $wrote, ([long]$effOut - [long]$wrote))

  [void][P]::CloseHandle($ch)
  [void][P]::CloseHandle($sh)
  Write-Host ""
}

# --- Pair 1: 256 writes of 64 bytes. The headline discriminator. ------------
MsgCell -Tag "ovh-msg-N256-S64"  -ReqQuota 65536 -N 256 -S 64  -PipeType 1 -ReadMode 1 `
        -Note "MESSAGE type/read mode, 256 messages of 64 bytes. Compare with ovh-byte-N256-S64, which differs ONLY in the pipe type and read mode."
MsgCell -Tag "ovh-byte-N256-S64" -ReqQuota 65536 -N 256 -S 64  -PipeType 0 -ReadMode 0 `
        -Note "BYTE-STREAM CONTROL for ovh-msg-N256-S64: identical total in identical chunk sizes, 256 writes of 64 bytes, no message framing. Any charge that appears here is a cost of issuing many small WRITES, not of many MESSAGES."

# --- Pair 2: same total, FEWER messages (64 x 256). -------------------------
MsgCell -Tag "ovh-msg-N64-S256"  -ReqQuota 65536 -N 64  -S 256 -PipeType 1 -ReadMode 1 `
        -Note "MESSAGE mode, same 16384-byte total as pair 1 but a quarter as many messages. Only N and S change from ovh-msg-N256-S64."
MsgCell -Tag "ovh-byte-N64-S256" -ReqQuota 65536 -N 64  -S 256 -PipeType 0 -ReadMode 0 `
        -Note "BYTE-STREAM CONTROL for ovh-msg-N64-S256."

# --- Pair 3: same total, MORE messages (512 x 32). --------------------------
MsgCell -Tag "ovh-msg-N512-S32"  -ReqQuota 65536 -N 512 -S 32  -PipeType 1 -ReadMode 1 `
        -Note "MESSAGE mode, same 16384-byte total as pairs 1 and 2 but twice as many messages as pair 1. If the difference tracks N rather than N*S, these three message cells show it directly."
MsgCell -Tag "ovh-byte-N512-S32" -ReqQuota 65536 -N 512 -S 32  -PipeType 0 -ReadMode 0 `
        -Note "BYTE-STREAM CONTROL for ovh-msg-N512-S32."

# --- Pair 4: same total in ONE message. The N=1 end of the N sweep. ---------
MsgCell -Tag "ovh-msg-N1-S16384"  -ReqQuota 65536 -N 1 -S 16384 -PipeType 1 -ReadMode 1 `
        -Note "MESSAGE mode, the same 16384-byte total as a SINGLE message. This is the N=1 point of the same sweep: with one message there is at most one message's overhead, so a fixed cost survives here and a per-message cost nearly vanishes."
MsgCell -Tag "ovh-byte-N1-S16384" -ReqQuota 65536 -N 1 -S 16384 -PipeType 0 -ReadMode 0 `
        -Note "BYTE-STREAM CONTROL for ovh-msg-N1-S16384."

Write-Output "########## end of probe ##########"
