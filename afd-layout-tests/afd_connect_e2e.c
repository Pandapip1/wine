/* End-to-end control table for the real IOCTL_AFD_CONNECT ioctl. ntdll only.
 *
 * Built for both x86_64 and i386 and run against a Wine build from this tree.
 * The connect request is written at explicit byte offsets: the AFD_CONNECT_INFO
 * head is sizeof(void*) * 3 bytes (phnt AFD_CONNECT_JOIN_INFO: BOOLEAN
 * SanActive; HANDLE RootEndpoint; HANDLE ConnectEndpoint), i.e. 24 on x86_64
 * and 12 on i386, followed by a TRANSPORT_ADDRESS with one TA_ADDRESS.
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <string.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS           ((NTSTATUS)0x00000000)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL  ((NTSTATUS)0xC0000023)
#endif
#ifndef STATUS_PENDING
#define STATUS_PENDING           ((NTSTATUS)0x00000103)
#endif

#define IOCTL_AFD_BIND        0x00012003u
#define IOCTL_AFD_CONNECT     0x00012007u
#define IOCTL_AFD_LISTEN      0x0001200Bu

NTSYSAPI NTSTATUS WINAPI NtCreateFile(PHANDLE,ACCESS_MASK,POBJECT_ATTRIBUTES,PIO_STATUS_BLOCK,
                                      PLARGE_INTEGER,ULONG,ULONG,ULONG,ULONG,PVOID,ULONG);
NTSYSAPI NTSTATUS WINAPI NtDeviceIoControlFile(HANDLE,HANDLE,PIO_APC_ROUTINE,PVOID,PIO_STATUS_BLOCK,
                                               ULONG,PVOID,ULONG,PVOID,ULONG);
NTSYSAPI NTSTATUS WINAPI NtClose(HANDLE);
NTSYSAPI NTSTATUS WINAPI NtWaitForSingleObject(HANDLE,BOOLEAN,PLARGE_INTEGER);

static int failures, checks;
static void check(int ok, const char *what, NTSTATUS got, NTSTATUS want)
{
    checks++;
    if (!ok) { failures++; printf("  FAIL %s: status %08lx (wanted %08lx)\n", what,
                                  (unsigned long)got, (unsigned long)want); }
    else printf("  ok   %s (status %08lx)\n", what, (unsigned long)got);
}

static ULONG build_ea(unsigned char *buf, int fam, int type, int proto)
{
    static const char name[] = "AfdOpenPacketXX";
    static const WCHAR tcp[] = L"\\Device\\Tcp";
    ULONG off, tdnl = (ULONG)sizeof(tcp);
    memset(buf, 0, 512);
    *(ULONG *)buf = 0;
    buf[4] = 0;
    buf[5] = 15;
    *(unsigned short *)(buf + 6) = (unsigned short)(24 + tdnl);
    memcpy(buf + 8, name, 15);
    off = 8 + 15;
    buf[off++] = 0;
    *(ULONG *)(buf + off + 0) = 0;
    *(ULONG *)(buf + off + 4) = 0;
    *(LONG *)(buf + off + 8) = fam;
    *(LONG *)(buf + off + 12) = type;
    *(LONG *)(buf + off + 16) = proto;
    *(ULONG *)(buf + off + 20) = tdnl;
    memcpy(buf + off + 24, tcp, tdnl);
    return off + 24 + tdnl;
}

static NTSTATUS open_afd(HANDLE *h)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK io;
    unsigned char ea[512];
    ULONG ea_len = build_ea(ea, 2 /*AF_INET*/, 1 /*SOCK_STREAM*/, 6 /*IPPROTO_TCP*/);
    static WCHAR path[] = L"\\Device\\Afd\\Endpoint";
    us.Buffer = path; us.Length = (USHORT)(wcslen(path) * 2); us.MaximumLength = us.Length + 2;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    return NtCreateFile(h, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &oa, &io, NULL, 0,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                        FILE_SYNCHRONOUS_IO_NONALERT, ea, ea_len);
}

static NTSTATUS sync_ioctl(HANDLE h, ULONG code, void *in, ULONG in_len, void *out, ULONG out_len)
{
    IO_STATUS_BLOCK io;
    NTSTATUS st = NtDeviceIoControlFile(h, NULL, NULL, NULL, &io, code, in, in_len, out, out_len);
    if (st == STATUS_PENDING) { NtWaitForSingleObject(h, FALSE, NULL); st = io.Status; }
    return st;
}

/* afd_bind_params { int unknown; struct sockaddr addr; }; out = bound sockaddr */
static NTSTATUS do_bind(HANDLE h, unsigned short port, unsigned short *bound_port)
{
    unsigned char in[20], out[32];
    NTSTATUS st;
    memset(in, 0, sizeof(in));
    memset(out, 0, sizeof(out));
    *(short *)(in + 4) = 2;                         /* sin_family = AF_INET  */
    *(unsigned short *)(in + 6) = port;             /* sin_port (big endian) */
    *(unsigned int *)(in + 8) = 0x0100007f;         /* 127.0.0.1             */
    st = sync_ioctl(h, IOCTL_AFD_BIND, in, sizeof(in), out, sizeof(out));
    if (!st && bound_port) *bound_port = *(unsigned short *)(out + 2);
    return st;
}

static NTSTATUS do_listen(HANDLE h)
{
    int p[3] = { 0, 8, 0 };
    return sync_ioctl(h, IOCTL_AFD_LISTEN, p, sizeof(p), NULL, 0);
}

/* head_size lets the caller force the wrong (ReactOS, 12-byte) layout. */
static ULONG build_connect(unsigned char *buf, ULONG head_size, unsigned short port_be)
{
    unsigned char *tail = buf + head_size;
    memset(buf, 0, head_size + 8 + 14);
    *(LONG *)(tail + 0) = 1;                        /* TAAddressCount        */
    *(unsigned short *)(tail + 4) = 14;             /* AddressLength         */
    *(unsigned short *)(tail + 6) = 2;              /* TDI_ADDRESS_TYPE_IP   */
    *(unsigned short *)(tail + 8) = port_be;        /* sin_port              */
    *(unsigned int *)(tail + 10) = 0x0100007f;      /* 127.0.0.1             */
    return head_size + 8 + 14;
}

int main(void)
{
    const ULONG native_head = (ULONG)(sizeof(void *) * 3);   /* 24 on x64, 12 on i386 */
    const ULONG reactos_head = 12;
    HANDLE listener = NULL, conn = NULL;
    unsigned char req[64];
    unsigned short port = 0;
    NTSTATUS st;
    ULONG len;

    printf("IOCTL_AFD_CONNECT end-to-end control table (%u-bit client, head = %u bytes)\n",
           (unsigned)(sizeof(void *) * 8), (unsigned)native_head);

    st = open_afd(&listener);
    if (st) { printf("  open listener failed %08lx\n", (unsigned long)st); return 2; }
    st = do_bind(listener, 0, &port);
    if (st) { printf("  bind listener failed %08lx\n", (unsigned long)st); return 2; }
    st = do_listen(listener);
    if (st) { printf("  listen failed %08lx\n", (unsigned long)st); return 2; }
    printf("  listener on 127.0.0.1 port %u\n", (unsigned)((port >> 8) | (port << 8)) & 0xffff);

    /* CASE A -- good request in this client's native layout: must SUCCEED. */
    st = open_afd(&conn);
    if (st) { printf("  open connector failed %08lx\n", (unsigned long)st); return 2; }
    if ((st = do_bind(conn, 0, NULL))) { printf("  bind connector failed %08lx\n", (unsigned long)st); return 2; }
    len = build_connect(req, native_head, port);
    st = sync_ioctl(conn, IOCTL_AFD_CONNECT, req, len, NULL, 0);
    check(st == STATUS_SUCCESS, "A: good native-layout connect succeeds", st, STATUS_SUCCESS);
    NtClose(conn); conn = NULL;

    /* CASE B -- truncated request: must be REJECTED, not read out of bounds. */
    st = open_afd(&conn);
    if (st) { printf("  open connector failed %08lx\n", (unsigned long)st); return 2; }
    if ((st = do_bind(conn, 0, NULL))) { printf("  bind connector failed %08lx\n", (unsigned long)st); return 2; }
    len = build_connect(req, native_head, port);
    st = sync_ioctl(conn, IOCTL_AFD_CONNECT, req, native_head + 8 - 1, NULL, 0);
    check(st == STATUS_BUFFER_TOO_SMALL, "B: truncated request rejected", st, STATUS_BUFFER_TOO_SMALL);
    NtClose(conn); conn = NULL;

    /* CASE C -- a request laid out the old ReactOS way.  On i386 that is the
     * same layout, so it must still succeed; on x86_64 it is 12 bytes short and
     * must NOT be parsed as a valid connect. */
    st = open_afd(&conn);
    if (st) { printf("  open connector failed %08lx\n", (unsigned long)st); return 2; }
    if ((st = do_bind(conn, 0, NULL))) { printf("  bind connector failed %08lx\n", (unsigned long)st); return 2; }
    len = build_connect(req, reactos_head, port);
    st = sync_ioctl(conn, IOCTL_AFD_CONNECT, req, len, NULL, 0);
    if (native_head == reactos_head)
        check(st == STATUS_SUCCESS, "C: i386 -- ReactOS layout is the same layout, still succeeds",
              st, STATUS_SUCCESS);
    else
        check(st != STATUS_SUCCESS, "C: x86_64 -- ReactOS-layout request must not connect", st, ~0u);
    NtClose(conn);
    NtClose(listener);

    printf("%d checks, %d failures\n", checks, failures);
    return failures != 0;
}
