/*
 * Structural byte-offset test for the real AFD_CONNECT ioctl input layout.
 *
 * Device-free and header-free on the parsing side: the two AFD_CONNECT_INFO
 * declarations are lifted verbatim out of include/wine/afd.h at build time by
 * afd_connect_layout_test.sh (which greps them into afd_connect_layout_gen.h),
 * and are used only to *build* requests, the way a client does.  The parser
 * below then reads those bytes back using nothing but the documented numeric
 * offsets, so a wrong header cannot make the test agree with itself.
 *
 * Sources for the numbers asserted here:
 *   phnt ntafd.h, AFD_CONNECT_JOIN_INFO { BOOLEAN SanActive; HANDLE
 *     RootEndpoint; HANDLE ConnectEndpoint; TRANSPORT_ADDRESS RemoteAddress; }
 *     -> RemoteAddress at +24 on Win64, +12 on Win32.
 *   ReactOS sdk/include/reactos/drivers/afd/shared.h at 763ce84cf5,
 *     AFD_CONNECT_INFO { BOOLEAN UseSAN; ULONG Root; ULONG Unknown;
 *     TRANSPORT_ADDRESS RemoteAddress; } -> RemoteAddress at +12 always.
 *     Kept here only as the wrong-layout control.
 *   mingw-w64 tdi.h: LONG TAAddressCount; then TA_ADDRESS { USHORT
 *     AddressLength; USHORT AddressType; UCHAR Address[]; }, and the packed
 *     TDI_ADDRESS_IP { USHORT sin_port; ULONG in_addr; UCHAR sin_zero[8]; } /
 *     TDI_ADDRESS_IP6 { USHORT sin6_port; ULONG sin6_flowinfo; USHORT
 *     sin6_addr[8]; ULONG sin6_scope_id; }.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>

typedef unsigned char  BOOLEAN;
typedef unsigned char  UCHAR;
typedef unsigned int   UINT;
typedef unsigned long long ULONGLONG;
#define C_ASSERT(e) extern int (*__c_assert__(void))[sizeof(struct { int _:1 - 2*!(e); })]

/* struct afd_connect_info_params_64 / _32, copied verbatim from the header. */
#include "afd_connect_layout_gen.h"

/* The wrong layout, for contrast: upstream ReactOS's AFD_CONNECT_INFO head. */
struct reactos_connect_info
{
    BOOLEAN use_san;
    UINT    root;
    UINT    unknown;
};

/* --- documented offsets, written out independently of any struct --- */
#define OFF_TAIL_64             24  /* phnt, Win64  */
#define OFF_TAIL_32             12  /* phnt, Win32 == ReactOS, both ABIs */
#define OFF_ADDR_COUNT           0
#define OFF_ADDR_LENGTH          4
#define OFF_ADDR_TYPE            6
#define OFF_ADDR                 8  /* fixed_tail = 4 + 2 + 2 */
#define FIXED_TAIL               8
#define TDI_ADDRESS_TYPE_IP      2
#define TDI_ADDRESS_TYPE_IP6    23

static int failures, checks;
#define CHECK(cond, fmt, ...) do { checks++; if (!(cond)) { \
    failures++; printf("  FAIL %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); } } while (0)

/* ------------------------------------------------------------------ */
/* client side: build a request the way ntdll/msafd would              */

static size_t build_request( unsigned char *buf, size_t head_size, int is_ip6,
                             unsigned short port_be, const unsigned char *addr_be,
                             unsigned int scope_be )
{
    unsigned short addr_len = is_ip6 ? 26 : 14;
    unsigned int count = 1;
    unsigned short type = is_ip6 ? TDI_ADDRESS_TYPE_IP6 : TDI_ADDRESS_TYPE_IP;
    unsigned char *tail;

    memset( buf, 0xcc, head_size + FIXED_TAIL + addr_len );  /* poison */
    memset( buf, 0, head_size );                             /* SanActive/handles = 0 */
    tail = buf + head_size;
    memcpy( tail + OFF_ADDR_COUNT,  &count,    4 );
    memcpy( tail + OFF_ADDR_LENGTH, &addr_len, 2 );
    memcpy( tail + OFF_ADDR_TYPE,   &type,     2 );
    memset( tail + OFF_ADDR, 0, addr_len );
    memcpy( tail + OFF_ADDR, &port_be, 2 );
    if (is_ip6)
    {
        memcpy( tail + OFF_ADDR + 6, addr_be, 16 );
        memcpy( tail + OFF_ADDR + 22, &scope_be, 4 );
    }
    else memcpy( tail + OFF_ADDR + 2, addr_be, 4 );
    return head_size + FIXED_TAIL + addr_len;
}

/* ------------------------------------------------------------------ */
/* server side: the parse, expressed purely in the documented offsets  */

struct parsed
{
    int      ok;            /* 0 = rejected */
    int      status_short;  /* rejected for length */
    int      family;        /* 2 = AF_INET, 23 = AF_INET6 */
    unsigned short port_be;
    unsigned char  addr[16];
    unsigned int   scope_be;
};

static struct parsed parse_request( const unsigned char *buf, size_t size, int client_is_64 )
{
    struct parsed p;
    size_t head = client_is_64 ? OFF_TAIL_64 : OFF_TAIL_32;
    const unsigned char *tail;
    unsigned int count;
    unsigned short addr_len, type;

    memset( &p, 0, sizeof(p) );
    if (size < head + FIXED_TAIL) { p.status_short = 1; return p; }
    tail = buf + head;
    memcpy( &count,    tail + OFF_ADDR_COUNT,  4 );
    memcpy( &addr_len, tail + OFF_ADDR_LENGTH, 2 );
    memcpy( &type,     tail + OFF_ADDR_TYPE,   2 );
    if (count != 1) return p;
    if ((size - head) - FIXED_TAIL < addr_len) return p;

    if (type == TDI_ADDRESS_TYPE_IP && addr_len >= 2 + 4)
    {
        p.family = 2;
        memcpy( &p.port_be, tail + OFF_ADDR, 2 );
        memcpy( p.addr, tail + OFF_ADDR + 2, 4 );
    }
    else if (type == TDI_ADDRESS_TYPE_IP6 && addr_len >= 2 + 4 + 16 + 4)
    {
        p.family = 23;
        memcpy( &p.port_be, tail + OFF_ADDR, 2 );
        memcpy( p.addr, tail + OFF_ADDR + 6, 16 );
        memcpy( &p.scope_be, tail + OFF_ADDR + 22, 4 );
    }
    else return p;
    p.ok = 1;
    return p;
}

/* ------------------------------------------------------------------ */

int main( void )
{
    static const unsigned char v4[4]  = { 93, 184, 216, 34 };
    static const unsigned char v6[16] = { 0x26,0x06,0x28,0x00,0x02,0x20,0x00,0x01,
                                          0x02,0x48,0x18,0x93,0x25,0xc8,0x19,0x46 };
    unsigned short port = 0x01bb;  /* 443, already big-endian on the wire */
    unsigned char buf[128], buf2[128];
    struct parsed p;
    size_t n, n2;

    printf( "AFD_CONNECT_INFO structural layout test\n" );

    /* 1. the header's own declarations must match the documented offsets */
    printf( "[1] header declarations vs phnt offsets\n" );
    CHECK( sizeof(struct afd_connect_info_params_64) == OFF_TAIL_64,
           "sizeof(_64) = %zu, want %d", sizeof(struct afd_connect_info_params_64), OFF_TAIL_64 );
    CHECK( sizeof(struct afd_connect_info_params_32) == OFF_TAIL_32,
           "sizeof(_32) = %zu, want %d", sizeof(struct afd_connect_info_params_32), OFF_TAIL_32 );
    CHECK( offsetof(struct afd_connect_info_params_64, root_endpoint) == 8, "RootEndpoint(64)" );
    CHECK( offsetof(struct afd_connect_info_params_64, connect_endpoint) == 16, "ConnectEndpoint(64)" );
    CHECK( offsetof(struct afd_connect_info_params_32, root_endpoint) == 4, "RootEndpoint(32)" );
    CHECK( offsetof(struct afd_connect_info_params_32, connect_endpoint) == 8, "ConnectEndpoint(32)" );

    /* 2. 64-bit client, IPv4: MUST parse (this is the case that was broken) */
    printf( "[2] 64-bit client, IPv4 -- must succeed\n" );
    n = build_request( buf, sizeof(struct afd_connect_info_params_64), 0, port, v4, 0 );
    CHECK( n == 24 + 8 + 14, "request size %zu, want 46", n );
    p = parse_request( buf, n, 1 );
    CHECK( p.ok && p.family == 2, "not parsed as AF_INET" );
    CHECK( p.port_be == port, "port %04x", p.port_be );
    CHECK( !memcmp( p.addr, v4, 4 ), "address mismatch" );

    /* 3. 64-bit client, IPv6: MUST parse */
    printf( "[3] 64-bit client, IPv6 -- must succeed\n" );
    n = build_request( buf, sizeof(struct afd_connect_info_params_64), 1, port, v6, 0x02000000 );
    CHECK( n == 24 + 8 + 26, "request size %zu, want 58", n );
    p = parse_request( buf, n, 1 );
    CHECK( p.ok && p.family == 23, "not parsed as AF_INET6" );
    CHECK( !memcmp( p.addr, v6, 16 ), "address mismatch" );
    CHECK( p.scope_be == 0x02000000, "scope %08x", p.scope_be );

    /* 4. CONTROL (must keep working): 32-bit client, IPv4 */
    printf( "[4] control: 32-bit client, IPv4 -- must still succeed\n" );
    n = build_request( buf, sizeof(struct afd_connect_info_params_32), 0, port, v4, 0 );
    CHECK( n == 12 + 8 + 14, "request size %zu, want 34", n );
    p = parse_request( buf, n, 0 );
    CHECK( p.ok && p.family == 2, "not parsed as AF_INET" );
    CHECK( !memcmp( p.addr, v4, 4 ), "address mismatch" );

    /* 5. CONTROL (i386 coincidence): on 32-bit the phnt and ReactOS layouts
     *    are byte-identical, so i386 behaviour cannot change. */
    printf( "[5] control: i386 phnt layout == i386 ReactOS layout, byte for byte\n" );
    CHECK( sizeof(struct reactos_connect_info) == sizeof(struct afd_connect_info_params_32),
           "ReactOS head %zu vs phnt-32 %zu", sizeof(struct reactos_connect_info),
           sizeof(struct afd_connect_info_params_32) );
    n  = build_request( buf,  sizeof(struct afd_connect_info_params_32), 0, port, v4, 0 );
    n2 = build_request( buf2, sizeof(struct reactos_connect_info),       0, port, v4, 0 );
    CHECK( n == n2 && !memcmp( buf, buf2, n ), "i386 request bytes differ between layouts" );

    /* 6. NEGATIVE CONTROL: truncated 64-bit request must be rejected, not read
     *    out of bounds.  31 bytes is one short of the 24 + 8 minimum, and is
     *    *longer* than the 12 + 8 a ReactOS-layout parser would have accepted,
     *    so this also catches a silent fall-back to the old size. */
    printf( "[6] negative control: truncated 64-bit request must be rejected\n" );
    memset( buf, 0, sizeof(buf) );
    build_request( buf, sizeof(struct afd_connect_info_params_64), 0, port, v4, 0 );
    p = parse_request( buf, 31, 1 );
    CHECK( !p.ok && p.status_short, "31-byte 64-bit request was not rejected" );
    p = parse_request( buf, 32, 1 );
    CHECK( !p.status_short, "32-byte 64-bit request wrongly rejected for length" );

    /* 7. NEGATIVE CONTROL: the test is not vacuous -- a request laid out the
     *    old (ReactOS) way must NOT parse correctly under the 64-bit parser. */
    printf( "[7] negative control: ReactOS-layout 64-bit request must not parse\n" );
    n = build_request( buf, sizeof(struct reactos_connect_info), 0, port, v4, 0 );
    p = parse_request( buf, n, 1 );
    CHECK( !(p.ok && p.family == 2 && p.port_be == port && !memcmp( p.addr, v4, 4 )),
           "the two layouts are indistinguishable -- test proves nothing" );

    printf( "\n%d checks, %d failures\n", checks, failures );
    return failures != 0;
}
