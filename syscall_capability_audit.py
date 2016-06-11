#!/usr/bin/python3

import argparse
import sys
import os
import logging
import re
import collections

# Good test cases:
# busybox
# dropbear

# Examples of false positive:
# ./netio.c:416:			TRACE(("socket() failed"))

# TODO add a 'ignore' CLI option list - some calls like socket() can be too noisy when starting from scratch

# TODO add an option to process 1/ either file by file + line by line, OR 2/ syscall by syscall on all sources

# TODO
# See Dive into Python 3 chap. 6 for inspiration
# "Code is code, data is data, and life is good"
# http://www.diveintopython3.net/generators.html

Syscall = collections.namedtuple('syscall', 'syscall require may_require')

WARNING_NO_HINT = 'this tool cannot provide any hint about which capabilities may be needed here'
WARNING_EXEC_FAMILY = 'WARNING: the exec* family syscalls may execute anything - ' + WARNING_NO_HINT

# Information tediously gathered via
# capabilities(7) and "man -wK CAP_FOOBAR | grep man2"
# man -wK CAP_ | grep man2 | sort | uniq
SYSCALLS = (

    # First, not a syscall yet very important to catch:

    Syscall('system',
            'WARNING: system() may execute anything - ' + WARNING_NO_HINT,
            None),

    # Now for the actual syscalls
    # man pages section 2 - System calls (functions provided by the kernel)
    # All the value of this tool is in this list. Keep it tidy!

    # First the "open door" ones

    Syscall('syscall',
            'WARNING: syscall() may be any syscall - ' + WARNING_NO_HINT,
            None), # we don't care about the obsolete _syscallX
    # The execve front-ends
    Syscall('execl', WARNING_EXEC_FAMILY, None),
    Syscall('execlp', WARNING_EXEC_FAMILY, None),
    Syscall('execle', WARNING_EXEC_FAMILY, None),
    Syscall('execv', WARNING_EXEC_FAMILY, None),
    Syscall('execvp', WARNING_EXEC_FAMILY, None),
    Syscall('execvpe', WARNING_EXEC_FAMILY, None),
    # execve itself and its brothers
    Syscall('execve', WARNING_EXEC_FAMILY, None),
    Syscall('execveat', WARNING_EXEC_FAMILY, None),
    Syscall('fexecve', WARNING_EXEC_FAMILY, None),

    # Now for the other syscalls, in alphabetical order

    Syscall('acct',
            'CAP_SYS_PACCT',
            None),
    Syscall('adjtimex',
            None,
            'CAP_SYS_TIME'),
    Syscall('bdflush',
            'CAP_SYS_ADMIN (Note: deprecated since Linux  2.6, this call does nothing.)',
            None),
    Syscall('bind',
            None,
            'CAP_NET_BIND_SERVICE for port numbers less than 1024'),
    Syscall('bpf',
            'CAP_SYS_ADMIN',
            None),
    Syscall('capset',
            'CAP_SETPCAP',
            None),
    Syscall('chmod',
            None,
            'CAP_FOWNER CAP_FSETID'),
    Syscall('chown',
            'CAP_CHOWN',
            None),
    Syscall('chroot',
            'CAP_SYS_CHROOT',
            None),
    Syscall('clone',
            None,
            'CAP_SYS_ADMIN,  Linux < 3.8: CAP_SYS_ADMIN CAP_SETUID CAP_SETGID'),
    Syscall('creat',
            None,
            'CAP_FOWNER'),
    Syscall('create_module',
            'CAP_SYS_MODULE',
            None),
    Syscall('delete_module',
            'CAP_SYS_MODULE',
            None),
    Syscall('epoll_ctl',
            None,
            'CAP_BLOCK_SUSPEND'),
    Syscall('fanotify_init',
            'CAP_SYS_ADMIN',
            None),
    Syscall('fchmod',
            None,
            'CAP_FOWNER CAP_FSETID'),
    Syscall('fchmodat',
            None,
            'CAP_FOWNER CAP_FSETID'),
    Syscall('fchown',
            'CAP_CHOWN',
            None),
    Syscall('fcntl',
            None,
            'CAP_LEASE CAP_SYS_RESOURCE CAP_FOWNER'),
    Syscall('fcntl64',
            None,
            'CAP_LEASE CAP_SYS_RESOURCE CAP_FOWNER'),
    Syscall('finit_module',
            'CAP_SYS_MODULE',
            None),
    Syscall('getpriority',
            None,
            'CAP_SYS_NICE'),
    Syscall('getrlimit',
            None,
            'CAP_SYS_RESOURCE'),
    Syscall('init_module',
            'CAP_SYS_MODULE',
            None),
    Syscall('ioctl',
            None,
            # SIOCSARP, SIOCDARP on AF_INET CAP_NET_ADMIN SIOCSPGRP on socket CAP_KILL TIOCSTI CAP_SYS_ADMIN
            'CAP_KILL CAP_SYS_ADMIN CAP_SYS_RAWIO CAP_SYS_RESOURCE CAP_SYS_TTY_CONFIG CAP_NET_ADMIN'),
    Syscall('ioperm',
            None,
            "CAP_SYS_RAWIO"),
    Syscall('iopl',
            None,
            'CAP_SYS_RAWIO'),
    Syscall('ioprio_set',
            None,
            'CAP_SYS_ADMIN CAP_SYS_NICE'),
    Syscall('kcmp',
            None,
            'CAP_SYS_PTRACE'),
    Syscall('kexec_file_load',
            'CAP_SYS_BOOT',
            None),
    Syscall('kexec_load',
            'CAP_SYS_BOOT',
            None),
    Syscall('keyctl',
            None,
            'CAP_SYS_ADMIN'),
    Syscall('kill',
            None,
            'CAP_KILL'),
    Syscall('killpg',
            None,
            'CAP_KILL'),
    Syscall('klogctl',
            None,
            'CAP_SYS_ADMIN (or better: CAP_SYSLOG)'),
    Syscall('lchown',
            'CAP_CHOWN',
            None),
    Syscall('lookup_dcookie',
            'CAP_SYS_ADMIN',
            None),
    Syscall('madvise',
            None,
            'CAP_SYS_ADMIN'),
    Syscall('mbind',
            None,
            'CAP_SYS_NICE'),
    Syscall('migrate_pages',
            None,
            'CAP_SYS_NICE'),
    Syscall('mknod',
            None,
            'CAP_MKNOD'),
    Syscall('mknodat',
            None,
            'CAP_MKNOD'),
    Syscall('mlock',
            None,
            'CAP_IPC_LOCK'),
    Syscall('mlock2',
            None,
            'CAP_IPC_LOCK'),
    Syscall('mlockall',
            None,
            'CAP_IPC_LOCK'),
    Syscall('mount',
            'CAP_SYS_ADMIN',
            None),
    Syscall('move_pages',
            None,
            'CAP_SYS_NICE'),
    Syscall('msgctl',
            None,
            'CAP_SYS_RESOURCE CAP_IPC_OWNER CAP_SYS_ADMIN'),
    Syscall('msgget',
            None,
            'CAP_IPC_OWNER'),
    Syscall('msgrcv',
            None,
            'CAP_IPC_OWNER'),
    Syscall('msgsnd',
            None,
            'CAP_IPC_OWNER'),
    Syscall('munlock',
            None,
            'CAP_IPC_LOCK'),
    Syscall('munlockall',
            None,
            'CAP_IPC_LOCK'),
    Syscall('nfsservctl',
            'CAP_SYS_ADMIN (Note: Since Linux 3.1, this system call no longer exists.)',
            None),
    Syscall('nice',
            None,
            'CAP_SYS_NICE'),
    Syscall('open',
            None,
            'CAP_FOWNER'),
    Syscall('openat',
            None,
            'CAP_FOWNER'),
    Syscall('open_by_handle_at',
            'CAP_DAC_READ_SEARCH',
            None),
    Syscall('pciconfig_read',
            'CAP_SYS_ADMIN',
            None),
    Syscall('pciconfig_write',
            'CAP_SYS_ADMIN',
            None),
    Syscall('perf_event_open',
            None,
            'CAP_SYS_ADMIN'),
    Syscall('pivot_root',
            'CAP_SYS_ADMIN',
            None),
    Syscall('prctl',
            None,
            'CAP_SETPCAP CAP_SYS_RESOURCE'),
    Syscall('prlimit',
            None,
            'CAP_SYS_ADMIN CAP_SYS_RESOURCE'),
    Syscall('process_vm_readv',
            None,
            'CAP_SYS_PTRACE'),
    Syscall('process_vm_writev',
            None,
            'CAP_SYS_PTRACE'),
    Syscall('ptrace',
            None,
            'CAP_SYS_ADMIN CAP_SYS_PTRACE'),
    Syscall('quotactl',
            None,
            'CAP_SYS_ADMIN'),
    Syscall('reboot',
            'CAP_SYS_BOOT',
            None),
    Syscall('rename',
            None,
            'CAP_MKNOD CAP_FOWNER'),
    Syscall('renameat',
            None,
            'CAP_MKNOD CAP_FOWNER'),
    Syscall('renameat2',
            None,
            'CAP_MKNOD CAP_FOWNER'),
    Syscall('rmdir',
            None,
            'CAP_FOWNER'),
    Syscall('sched_setaffinity',
            None,
            'CAP_SYS_NICE'),
    Syscall('sched_setattr',
            # Too broad: sched_setattr(2) does not mention specific capability,
            # yet may fail with errno "EPERM  The caller does not have appropriate privileges."
            # See sched(7). We'll take a conservative approach:
            None,
            'CAP_SYS_NICE'),
    Syscall('sched_setparam',
            'CAP_SYS_NICE',
            None),
    Syscall('sched_setscheduler',
            None,
            'CAP_SYS_NICE'),
    Syscall('seccomp',
            None,
            'CAP_SYS_ADMIN'),
    Syscall('semctl',
            None,
            'CAP_IPC_OWNER CAP_SYS_ADMIN'),
    Syscall('semget',
            None,
            'CAP_IPC_OWNER'),
    Syscall('semop',
            None,
            'CAP_IPC_OWNER'),
    Syscall('semtimedop',
            None,
            'CAP_IPC_OWNER'),
    Syscall('setdomainname',
            'CAP_SYS_ADMIN',
            None),
    Syscall('seteuid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETUID',
            None),
    Syscall('setfsgid',
            'CAP_SETGID',
            None),
    Syscall('setfsuid',
            'CAP_SETUID',
            None),
    Syscall('setgid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETGID',
            None),
    Syscall('setgroups',
            'CAP_SETGID',
            None),
    Syscall('sethostname',
            'CAP_SYS_ADMIN',
            None),
    Syscall('setns',
            None,
            # difference between present time vs target namespace
            'CAP_SYS_CHROOT CAP_SYS_ADMIN'),
    Syscall('setpriority',
            None,
            'CAP_SYS_NICE'),
    Syscall('setreuid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETUID',
            None),
    Syscall('setregid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETGID',
            None),
    Syscall('setresuid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETUID',
            None),
    Syscall('setresgid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETGID',
            None),
    Syscall('setrlimit',
            None,
            'CAP_SYS_ADMIN CAP_SYS_RESOURCE'),
    Syscall('setsockopt',
            None,
            'CAP_NET_ADMIN'),
    Syscall('settimeofday',
            'CAP_SYS_TIME',
            None),
    Syscall('setuid',
            # stricly speaking, this is not required - but for any meaningful use, it is
            'CAP_SETUID',
            None),
    Syscall('set_robust_list',
            None,
            'CAP_SYS_PTRACE'),
    Syscall('shmctl',
            None,
            'CAP_IPC_OWNER CAP_SYS_ADMIN'),
    Syscall('shmget',
            None,
            'CAP_IPC_LOCK CAP_IPC_OWNER'),
    Syscall('shmat',
            None,
            'CAP_IPC_OWNER'),
    Syscall('shmdt',
            None,
            'CAP_IPC_OWNER'),
    Syscall('sigqueue',
            None,
            'CAP_KILL'), # see kill(2)
    Syscall('socket',
            None,
            # besides the documented RAW and PACKET sockets, also for AF_INET/SOCK_DGRAM (why???)
            'CAP_NET_RAW'),
    Syscall('spu_create', # specific to PowerPC machines
            None,
            'CAP_SYS_NICE'),
    Syscall('stime',
            'CAP_SYS_TIME',
            None),
    Syscall('swapoff',
            'CAP_SYS_ADMIN',
            None),
    Syscall('swapon',
            'CAP_SYS_ADMIN',
            None),
    Syscall('umount',
            'CAP_SYS_ADMIN',
            None),
    Syscall('umount2',
            'CAP_SYS_ADMIN',
            None),
    Syscall('unlink',
            None,
            'CAP_FOWNER'),
    Syscall('unlinkat',
            None,
            'CAP_FOWNER'),
    Syscall('unshare',
            None,
            'see unshare(2) - often CAP_SYS_ADMIN, Linux kernel version dependant'),
    Syscall('utime',
            None,
            'CAP_DAC_OVERRIDE CAP_FOWNER'),
    Syscall('utimes',
            None,
            'CAP_DAC_OVERRIDE CAP_FOWNER'),
    Syscall('vhangup',
            'CAP_SYS_TTY_CONFIG',
            None),
    Syscall('vm86', # specific to 32-bit Intel processors
            None,
            'CAP_SYS_ADMIN'),
    Syscall('vm86old', # specific to 32-bit Intel processors
            None,
            'CAP_SYS_ADMIN')

    # TODO these are not documented capability wise - see xattr(7)
    # getxattr(2), listxattr(2), removexattr(2), setxattr(2)

    # TODO pthread_setschedparam(3)
    # TODO pthread_setschedprio(3)
)

CANNOT_IGNORE = (
    'system',
    'syscall',
    'execl',
    'execlp',
    'execle',
    'execv',
    'execvp',
    'execvpe',
    'execve',
    'execveat',
    'fexecve'
)

SRC_FILES_SUFFIXES = (
    '.c', '.h',
    '.cpp', '.hpp',
    '.cc', '.hh',
    '.cxx', '.hxx'
    '.C', '.H', # rare, yet used (example gcc source code)
    '.c++', 'h++' # some say this has been used, though not available on some file systems
    # Never met these, but:
    # http://stackoverflow.com/a/5171821/5257515
    # "some are using .ii, .ixx, .ipp, .inl for headers providing inline definitions
    # and .txx, .tpp and .tpl for template definitions"
    '.ii', '.ixx', '.ipp', '.inl',
    '.txx', '.tpp', '.tpl'
)

class ColorCode:
    GREEN = '\033[92m'
    ORANGE = '\033[93m'
    RED = '\033[91m'
    NEUTRAL = '\033[0m'

def syscall_listing():
    for call in SYSCALLS:
        if call.require:
            print("%s: %s"
                  % (call.syscall, call.require))
        if call.may_require:
            print("%s: may require %s"
                  % (call.syscall, call.may_require))

def sanitize_ignored(ignored_list):
    for call in ignored_list:
        if call in CANNOT_IGNORE:
            print("WARNING:'%s' cannot be ignored - removing from list of ignored calls" % call)
    ignore = [call for call in ignored_list if call not in CANNOT_IGNORE]
    return ignore

def is_source(file):
    _, file_extension = os.path.splitext(file)
    return file_extension in SRC_FILES_SUFFIXES

def main():
    parser = argparse.ArgumentParser(description='Scan source code for syscalls requiring capabilities.')
    parser.add_argument('-d',
                        '--directory',
                        help='Top level source code directory.',
                        metavar='topleveldir', type=str)
    parser.add_argument('-l',
                        '--listing',
                        help='List managed syscalls and corresponding capabilities.',
                        action='store_true')
    parser.add_argument('-i',
                        '--ignore',
                        help="""Comma separated list of syscalls to ignore
                        This may be usefull if source code uses custom function or method
                        named the same way as syscalls, or if you prefer not to get output
                        for potentialy noisy syscalls such as open(), socket(), or ioctl().
                        system(3), syscall(2) and the exec*(2) family cannot be ignored.""",
                        metavar='ig1,ig2,...', type=str)
    parser.add_argument('-v',
                        '--verbose',
                        help='Increase processing verbosity.',
                        action='store_true')
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()
    if args.verbose:
        verbosity = logging.DEBUG
    else:
        verbosity = logging.INFO
    logging.basicConfig(format='%(levelname)s:%(message)s', level=verbosity)

    if args.listing:
        syscall_listing()
        sys.exit(0)

    ignored = args.ignore.split(',')
    ignored = sanitize_ignored(ignored)

    if not os.path.isdir(args.directory) or not os.access(args.directory, os.R_OK):
        logging.error("Could not open directory '%s', aborting.", args.directory)
        sys.exit(1)

    logging.debug("Processing files in %s... ", args.directory)
    # TODO: build 3 sets for 'syscall', 'required' and 'may be required' capabilities,
    # output at the end of processing as global final result
    for dirpath, _, filenames in os.walk(args.directory):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            logging.debug("Processing file '%s'... ", fpath)
            if not is_source(fpath):
                continue
            logging.debug("Scanning source file '%s'", fpath)
            # source files are _supposed_ to be small, this pattern should be OK
            # f = open(fpath, "r") # this choke on busybox/modutils/modutils-24.c, with a "UnicodeDecodeError: 'utf-8' codec can't decode byte"
            f = open(fpath, "r", encoding="ISO-8859-1")
            lines = f.readlines()
            f.close()
            # TODO maybe rather do a loop other syscalls (and then lines),
            # to get a summary file by file, syscall by syscall, all lines matching a syscall?
            for linenum, line in enumerate(lines):
                for call in SYSCALLS:
                    if call.syscall in ignored:
                        continue
                    # very inefficient to recreate a regexp each time
                    pattern = r'\b' + call.syscall + r'\b' + r'\s*\('   # r'\('
                    if re.search(pattern, line):
                        print("%s:%d:%s"
                              % (fpath, linenum + 1, line), end='')
                        if call.require:
                            print(ColorCode.RED, end='')
                            print("syscall '%s': %s"
                                  % (call.syscall, call.require))
                            print(ColorCode.NEUTRAL, end='')
                        if call.may_require:
                            print(ColorCode.ORANGE, end='')
                            print("syscall '%s' may require %s"
                                  % (call.syscall, call.may_require))
                            print(ColorCode.NEUTRAL, end='')
    print("Done processing files in '%s'." % args.directory)


if __name__ == "__main__":
    main()
