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
  [StructLayout(LayoutKind.Sequential)] public struct ZD { public long Offset; public long Beyond; }
  public const uint FSCTL_SET_SPARSE    = 0x000900C4;
  public const uint FSCTL_SET_ZERO_DATA = 0x000980C8;
  public static string Std(IntPtr h) {
    byte[] io = new byte[16]; byte[] b = new byte[24];
    int st = NtQueryInformationFile(h, io, b, 24, 5);
    long alloc = BitConverter.ToInt64(b,0), eof = BitConverter.ToInt64(b,8);
    return string.Format("EndOfFile={0,-7} Alloc={1,-7} (st=0x{2:x8})", eof, alloc, st);
  }
}
"@
Add-Type -TypeDefinition $cs

function Run([bool]$sparse, [string]$tag) {
  $p = Join-Path $env:TEMP "zd-$tag.bin"
  if (Test-Path $p) { Remove-Item $p -Force }
  $fs = [System.IO.File]::Open($p,'Create','ReadWrite','None')
  $h  = $fs.SafeFileHandle.DangerousGetHandle()
  Write-Output "[$tag] sparse-marked=$sparse"
  if ($sparse) {
    $r = 0
    $ok = [P]::DeviceIoControl($h,[P]::FSCTL_SET_SPARSE,[IntPtr]::Zero,0,[IntPtr]::Zero,0,[ref]$r,[IntPtr]::Zero)
    Write-Output ("    FSCTL_SET_SPARSE ok={0} err={1}" -f $ok,[Runtime.InteropServices.Marshal]::GetLastWin32Error())
  }
  $buf = New-Object byte[] 65536
  for ($i=0; $i -lt 65536; $i++) { $buf[$i] = 0x78 }
  $fs.Write($buf,0,65536); $fs.Flush($true)
  Write-Output ("    after writing 65536   {0}" -f [P]::Std($h))
  $z = New-Object P+ZD; $z.Offset = 8192; $z.Beyond = 40960
  $sz = [Runtime.InteropServices.Marshal]::SizeOf($z)
  $pz = [Runtime.InteropServices.Marshal]::AllocHGlobal($sz)
  [Runtime.InteropServices.Marshal]::StructureToPtr($z,$pz,$false)
  $r = 0
  $ok = [P]::DeviceIoControl($h,[P]::FSCTL_SET_ZERO_DATA,$pz,$sz,[IntPtr]::Zero,0,[ref]$r,[IntPtr]::Zero)
  Write-Output ("    SET_ZERO_DATA(8192..40960) ok={0} err={1}" -f $ok,[Runtime.InteropServices.Marshal]::GetLastWin32Error())
  [Runtime.InteropServices.Marshal]::FreeHGlobal($pz)
  Write-Output ("    after zero_data       {0}" -f [P]::Std($h))
  $fs.Position = 8192
  $chk = New-Object byte[] 16
  [void]$fs.Read($chk,0,16)
  $nz = 0; foreach ($b in $chk) { if ($b -ne 0) { $nz++ } }
  Write-Output ("    bytes at 8192 all zero? {0}" -f ($nz -eq 0))
  Write-Output "    DISCRIMINATOR: Alloc unchanged => zeroed in place; Alloc dropped => deallocated"
  $fs.Close(); Remove-Item $p -Force
}
Run $true  "sparse"
Run $false "nonsparse"
