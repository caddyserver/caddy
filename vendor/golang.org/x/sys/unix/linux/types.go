// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build ignore

/*
Input to cgo -godefs.  See README.md
*/

// +godefs map struct_in_addr [4]byte /* in_addr */
// +godefs map struct_in6_addr [16]byte /* in6_addr */

package unix

/*
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#define _GNU_SOURCE

#include <dirent.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/signal.h>
#include <sys/statfs.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <linux/filter.h>
#include <linux/keyctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/icmpv6.h>
#include <asm/termbits.h>
#include <asm/ptrace.h>
#include <time.h>
#include <unistd.h>
#include <ustat.h>
#include <utime.h>
#include <linux/can.h>
#include <linux/if_alg.h>
#include <linux/fs.h>
#include <linux/vm_sockets.h>
#include <linux/random.h>

// On mips64, the glibc stat and kernel stat do not agree
#if (defined(__mips__) && _MIPS_SIM == _MIPS_SIM_ABI64)

// Use the stat defined by the kernel with a few modifications. These are:
//	* The time fields (like st_atime and st_atimensec) use the timespec
//	  struct (like st_atim) for consitancy with the glibc fields.
//	* The padding fields get different names to not break compatibility.
//	* st_blocks is signed, again for compatibility.
struct stat {
	unsigned int		st_dev;
	unsigned int		st_pad1[3]; // Reserved for st_dev expansion

	unsigned long		st_ino;

	mode_t			st_mode;
	__u32			st_nlink;

	uid_t			st_uid;
	gid_t			st_gid;

	unsigned int		st_rdev;
	unsigned int		st_pad2[3]; // Reserved for st_rdev expansion

	off_t			st_size;

	// These are declared as speperate fields in the kernel. Here we use
	// the timespec struct for consistancy with the other stat structs.
	struct timespec		st_atim;
	struct timespec		st_mtim;
	struct timespec		st_ctim;

	unsigned int		st_blksize;
	unsigned int		st_pad4;

	long			st_blocks;
};

// These are needed because we do not include fcntl.h or sys/types.h
#include <linux/fcntl.h>
#include <linux/fadvise.h>

#else

// Use the stat defined by glibc
#include <fcntl.h>
#include <sys/types.h>

#endif

// Certain constants and structs are missing from the fs/crypto UAPI
#define FS_MAX_KEY_SIZE                 64
struct fscrypt_key {
  __u32 mode;
  __u8 raw[FS_MAX_KEY_SIZE];
  __u32 size;
};

#ifdef TCSETS2
// On systems that have "struct termios2" use this as type Termios.
typedef struct termios2 termios_t;
#else
typedef struct termios termios_t;
#endif

enum {
	sizeofPtr = sizeof(void*),
};

union sockaddr_all {
	struct sockaddr s1;	// this one gets used for fields
	struct sockaddr_in s2;	// these pad it out
	struct sockaddr_in6 s3;
	struct sockaddr_un s4;
	struct sockaddr_ll s5;
	struct sockaddr_nl s6;
};

struct sockaddr_any {
	struct sockaddr addr;
	char pad[sizeof(union sockaddr_all) - sizeof(struct sockaddr)];
};

// copied from /usr/include/bluetooth/hci.h
struct sockaddr_hci {
        sa_family_t     hci_family;
        unsigned short  hci_dev;
        unsigned short  hci_channel;
};;

// copied from /usr/include/linux/un.h
struct my_sockaddr_un {
	sa_family_t sun_family;
#if defined(__ARM_EABI__) || defined(__powerpc64__)
	// on ARM char is by default unsigned
	signed char sun_path[108];
#else
	char sun_path[108];
#endif
};

#ifdef __ARM_EABI__
typedef struct user_regs PtraceRegs;
#elif defined(__aarch64__)
typedef struct user_pt_regs PtraceRegs;
#elif defined(__mips__) || defined(__powerpc64__)
typedef struct pt_regs PtraceRegs;
#elif defined(__s390x__)
typedef struct _user_regs_struct PtraceRegs;
#elif defined(__sparc__)
#include <asm/ptrace.h>
typedef struct pt_regs PtraceRegs;
#else
typedef struct user_regs_struct PtraceRegs;
#endif

#if defined(__s390x__)
typedef struct _user_psw_struct ptracePsw;
typedef struct _user_fpregs_struct ptraceFpregs;
typedef struct _user_per_struct ptracePer;
#else
typedef struct {} ptracePsw;
typedef struct {} ptraceFpregs;
typedef struct {} ptracePer;
#endif

// The real epoll_event is a union, and godefs doesn't handle it well.
struct my_epoll_event {
	uint32_t events;
#if defined(__ARM_EABI__) || defined(__aarch64__) || (defined(__mips__) && _MIPS_SIM == _ABIO32)
	// padding is not specified in linux/eventpoll.h but added to conform to the
	// alignment requirements of EABI
	int32_t padFd;
#elif defined(__powerpc64__) || defined(__s390x__) || defined(__sparc__)
	int32_t _padFd;
#endif
	int32_t fd;
	int32_t pad;
};

*/
import "C"

// Machine characteristics; for internal use.

const (
	sizeofPtr      = C.sizeofPtr
	sizeofShort    = C.sizeof_short
	sizeofInt      = C.sizeof_int
	sizeofLong     = C.sizeof_long
	sizeofLongLong = C.sizeof_longlong
	PathMax        = C.PATH_MAX
)

// Basic types

type (
	_C_short     C.short
	_C_int       C.int
	_C_long      C.long
	_C_long_long C.longlong
)

// Time

type Timespec C.struct_timespec

type Timeval C.struct_timeval

type Timex C.struct_timex

type Time_t C.time_t

type Tms C.struct_tms

type Utimbuf C.struct_utimbuf

// Processes

type Rusage C.struct_rusage

type Rlimit C.struct_rlimit

type _Gid_t C.gid_t

// Files

type Stat_t C.struct_stat

type Statfs_t C.struct_statfs

type Dirent C.struct_dirent

type Fsid C.fsid_t

type Flock_t C.struct_flock

// Filesystem Encryption

type FscryptPolicy C.struct_fscrypt_policy

type FscryptKey C.struct_fscrypt_key

// Structure for Keyctl

type KeyctlDHParams C.struct_keyctl_dh_params

// Advice to Fadvise

const (
	FADV_NORMAL     = C.POSIX_FADV_NORMAL
	FADV_RANDOM     = C.POSIX_FADV_RANDOM
	FADV_SEQUENTIAL = C.POSIX_FADV_SEQUENTIAL
	FADV_WILLNEED   = C.POSIX_FADV_WILLNEED
	FADV_DONTNEED   = C.POSIX_FADV_DONTNEED
	FADV_NOREUSE    = C.POSIX_FADV_NOREUSE
)

// Sockets

type RawSockaddrInet4 C.struct_sockaddr_in

type RawSockaddrInet6 C.struct_sockaddr_in6

type RawSockaddrUnix C.struct_my_sockaddr_un

type RawSockaddrLinklayer C.struct_sockaddr_ll

type RawSockaddrNetlink C.struct_sockaddr_nl

type RawSockaddrHCI C.struct_sockaddr_hci

type RawSockaddrCAN C.struct_sockaddr_can

type RawSockaddrALG C.struct_sockaddr_alg

type RawSockaddrVM C.struct_sockaddr_vm

type RawSockaddr C.struct_sockaddr

type RawSockaddrAny C.struct_sockaddr_any

type _Socklen C.socklen_t

type Linger C.struct_linger

type Iovec C.struct_iovec

type IPMreq C.struct_ip_mreq

type IPMreqn C.struct_ip_mreqn

type IPv6Mreq C.struct_ipv6_mreq

type Msghdr C.struct_msghdr

type Cmsghdr C.struct_cmsghdr

type Inet4Pktinfo C.struct_in_pktinfo

type Inet6Pktinfo C.struct_in6_pktinfo

type IPv6MTUInfo C.struct_ip6_mtuinfo

type ICMPv6Filter C.struct_icmp6_filter

type Ucred C.struct_ucred

type TCPInfo C.struct_tcp_info

const (
	SizeofSockaddrInet4     = C.sizeof_struct_sockaddr_in
	SizeofSockaddrInet6     = C.sizeof_struct_sockaddr_in6
	SizeofSockaddrAny       = C.sizeof_struct_sockaddr_any
	SizeofSockaddrUnix      = C.sizeof_struct_sockaddr_un
	SizeofSockaddrLinklayer = C.sizeof_struct_sockaddr_ll
	SizeofSockaddrNetlink   = C.sizeof_struct_sockaddr_nl
	SizeofSockaddrHCI       = C.sizeof_struct_sockaddr_hci
	SizeofSockaddrCAN       = C.sizeof_struct_sockaddr_can
	SizeofSockaddrALG       = C.sizeof_struct_sockaddr_alg
	SizeofSockaddrVM        = C.sizeof_struct_sockaddr_vm
	SizeofLinger            = C.sizeof_struct_linger
	SizeofIPMreq            = C.sizeof_struct_ip_mreq
	SizeofIPMreqn           = C.sizeof_struct_ip_mreqn
	SizeofIPv6Mreq          = C.sizeof_struct_ipv6_mreq
	SizeofMsghdr            = C.sizeof_struct_msghdr
	SizeofCmsghdr           = C.sizeof_struct_cmsghdr
	SizeofInet4Pktinfo      = C.sizeof_struct_in_pktinfo
	SizeofInet6Pktinfo      = C.sizeof_struct_in6_pktinfo
	SizeofIPv6MTUInfo       = C.sizeof_struct_ip6_mtuinfo
	SizeofICMPv6Filter      = C.sizeof_struct_icmp6_filter
	SizeofUcred             = C.sizeof_struct_ucred
	SizeofTCPInfo           = C.sizeof_struct_tcp_info
)

// Netlink routing and interface messages

const (
	IFA_UNSPEC          = C.IFA_UNSPEC
	IFA_ADDRESS         = C.IFA_ADDRESS
	IFA_LOCAL           = C.IFA_LOCAL
	IFA_LABEL           = C.IFA_LABEL
	IFA_BROADCAST       = C.IFA_BROADCAST
	IFA_ANYCAST         = C.IFA_ANYCAST
	IFA_CACHEINFO       = C.IFA_CACHEINFO
	IFA_MULTICAST       = C.IFA_MULTICAST
	IFLA_UNSPEC         = C.IFLA_UNSPEC
	IFLA_ADDRESS        = C.IFLA_ADDRESS
	IFLA_BROADCAST      = C.IFLA_BROADCAST
	IFLA_IFNAME         = C.IFLA_IFNAME
	IFLA_MTU            = C.IFLA_MTU
	IFLA_LINK           = C.IFLA_LINK
	IFLA_QDISC          = C.IFLA_QDISC
	IFLA_STATS          = C.IFLA_STATS
	IFLA_COST           = C.IFLA_COST
	IFLA_PRIORITY       = C.IFLA_PRIORITY
	IFLA_MASTER         = C.IFLA_MASTER
	IFLA_WIRELESS       = C.IFLA_WIRELESS
	IFLA_PROTINFO       = C.IFLA_PROTINFO
	IFLA_TXQLEN         = C.IFLA_TXQLEN
	IFLA_MAP            = C.IFLA_MAP
	IFLA_WEIGHT         = C.IFLA_WEIGHT
	IFLA_OPERSTATE      = C.IFLA_OPERSTATE
	IFLA_LINKMODE       = C.IFLA_LINKMODE
	IFLA_LINKINFO       = C.IFLA_LINKINFO
	IFLA_NET_NS_PID     = C.IFLA_NET_NS_PID
	IFLA_IFALIAS        = C.IFLA_IFALIAS
	IFLA_MAX            = C.IFLA_MAX
	RT_SCOPE_UNIVERSE   = C.RT_SCOPE_UNIVERSE
	RT_SCOPE_SITE       = C.RT_SCOPE_SITE
	RT_SCOPE_LINK       = C.RT_SCOPE_LINK
	RT_SCOPE_HOST       = C.RT_SCOPE_HOST
	RT_SCOPE_NOWHERE    = C.RT_SCOPE_NOWHERE
	RT_TABLE_UNSPEC     = C.RT_TABLE_UNSPEC
	RT_TABLE_COMPAT     = C.RT_TABLE_COMPAT
	RT_TABLE_DEFAULT    = C.RT_TABLE_DEFAULT
	RT_TABLE_MAIN       = C.RT_TABLE_MAIN
	RT_TABLE_LOCAL      = C.RT_TABLE_LOCAL
	RT_TABLE_MAX        = C.RT_TABLE_MAX
	RTA_UNSPEC          = C.RTA_UNSPEC
	RTA_DST             = C.RTA_DST
	RTA_SRC             = C.RTA_SRC
	RTA_IIF             = C.RTA_IIF
	RTA_OIF             = C.RTA_OIF
	RTA_GATEWAY         = C.RTA_GATEWAY
	RTA_PRIORITY        = C.RTA_PRIORITY
	RTA_PREFSRC         = C.RTA_PREFSRC
	RTA_METRICS         = C.RTA_METRICS
	RTA_MULTIPATH       = C.RTA_MULTIPATH
	RTA_FLOW            = C.RTA_FLOW
	RTA_CACHEINFO       = C.RTA_CACHEINFO
	RTA_TABLE           = C.RTA_TABLE
	RTN_UNSPEC          = C.RTN_UNSPEC
	RTN_UNICAST         = C.RTN_UNICAST
	RTN_LOCAL           = C.RTN_LOCAL
	RTN_BROADCAST       = C.RTN_BROADCAST
	RTN_ANYCAST         = C.RTN_ANYCAST
	RTN_MULTICAST       = C.RTN_MULTICAST
	RTN_BLACKHOLE       = C.RTN_BLACKHOLE
	RTN_UNREACHABLE     = C.RTN_UNREACHABLE
	RTN_PROHIBIT        = C.RTN_PROHIBIT
	RTN_THROW           = C.RTN_THROW
	RTN_NAT             = C.RTN_NAT
	RTN_XRESOLVE        = C.RTN_XRESOLVE
	RTNLGRP_NONE        = C.RTNLGRP_NONE
	RTNLGRP_LINK        = C.RTNLGRP_LINK
	RTNLGRP_NOTIFY      = C.RTNLGRP_NOTIFY
	RTNLGRP_NEIGH       = C.RTNLGRP_NEIGH
	RTNLGRP_TC          = C.RTNLGRP_TC
	RTNLGRP_IPV4_IFADDR = C.RTNLGRP_IPV4_IFADDR
	RTNLGRP_IPV4_MROUTE = C.RTNLGRP_IPV4_MROUTE
	RTNLGRP_IPV4_ROUTE  = C.RTNLGRP_IPV4_ROUTE
	RTNLGRP_IPV4_RULE   = C.RTNLGRP_IPV4_RULE
	RTNLGRP_IPV6_IFADDR = C.RTNLGRP_IPV6_IFADDR
	RTNLGRP_IPV6_MROUTE = C.RTNLGRP_IPV6_MROUTE
	RTNLGRP_IPV6_ROUTE  = C.RTNLGRP_IPV6_ROUTE
	RTNLGRP_IPV6_IFINFO = C.RTNLGRP_IPV6_IFINFO
	RTNLGRP_IPV6_PREFIX = C.RTNLGRP_IPV6_PREFIX
	RTNLGRP_IPV6_RULE   = C.RTNLGRP_IPV6_RULE
	RTNLGRP_ND_USEROPT  = C.RTNLGRP_ND_USEROPT
	SizeofNlMsghdr      = C.sizeof_struct_nlmsghdr
	SizeofNlMsgerr      = C.sizeof_struct_nlmsgerr
	SizeofRtGenmsg      = C.sizeof_struct_rtgenmsg
	SizeofNlAttr        = C.sizeof_struct_nlattr
	SizeofRtAttr        = C.sizeof_struct_rtattr
	SizeofIfInfomsg     = C.sizeof_struct_ifinfomsg
	SizeofIfAddrmsg     = C.sizeof_struct_ifaddrmsg
	SizeofRtMsg         = C.sizeof_struct_rtmsg
	SizeofRtNexthop     = C.sizeof_struct_rtnexthop
)

type NlMsghdr C.struct_nlmsghdr

type NlMsgerr C.struct_nlmsgerr

type RtGenmsg C.struct_rtgenmsg

type NlAttr C.struct_nlattr

type RtAttr C.struct_rtattr

type IfInfomsg C.struct_ifinfomsg

type IfAddrmsg C.struct_ifaddrmsg

type RtMsg C.struct_rtmsg

type RtNexthop C.struct_rtnexthop

// Linux socket filter

const (
	SizeofSockFilter = C.sizeof_struct_sock_filter
	SizeofSockFprog  = C.sizeof_struct_sock_fprog
)

type SockFilter C.struct_sock_filter

type SockFprog C.struct_sock_fprog

// Inotify

type InotifyEvent C.struct_inotify_event

const SizeofInotifyEvent = C.sizeof_struct_inotify_event

// Ptrace

// Register structures
type PtraceRegs C.PtraceRegs

// Structures contained in PtraceRegs on s390x (exported by mkpost.go)
type PtracePsw C.ptracePsw

type PtraceFpregs C.ptraceFpregs

type PtracePer C.ptracePer

// Misc

type FdSet C.fd_set

type Sysinfo_t C.struct_sysinfo

type Utsname C.struct_utsname

type Ustat_t C.struct_ustat

type EpollEvent C.struct_my_epoll_event

const (
	AT_FDCWD            = C.AT_FDCWD
	AT_REMOVEDIR        = C.AT_REMOVEDIR
	AT_SYMLINK_FOLLOW   = C.AT_SYMLINK_FOLLOW
	AT_SYMLINK_NOFOLLOW = C.AT_SYMLINK_NOFOLLOW
)

type PollFd C.struct_pollfd

const (
	POLLIN    = C.POLLIN
	POLLPRI   = C.POLLPRI
	POLLOUT   = C.POLLOUT
	POLLRDHUP = C.POLLRDHUP
	POLLERR   = C.POLLERR
	POLLHUP   = C.POLLHUP
	POLLNVAL  = C.POLLNVAL
)

type Sigset_t C.sigset_t

const RNDGETENTCNT = C.RNDGETENTCNT

// sysconf information

const _SC_PAGESIZE = C._SC_PAGESIZE

// Terminal handling

type Termios C.termios_t
