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

# Examples of false positives:
# dropbear: no parameter + inside string: ./netio.c:416: TRACE(("socket() failed"))

# TODO add an option to process 1/ either file by file + line by line, OR 2/ syscall by syscall on all sources
# TODO selfcheck: build a list of all capabilities, check if some are not handled here

# TODO
# See Dive into Python 3 chap. 6 for inspiration
# "Code is code, data is data, and life is good"
# http://www.diveintopython3.net/generators.html

WARNING_NO_HINT = 'this tool cannot provide any hint about which capabilities may be needed here'
WARNING_EXEC_FAMILY = 'WARNING: the exec* syscalls family may execute anything - ' + WARNING_NO_HINT

# Information tediously gathered via
# capabilities(7) and "man -wK CAP_FOOBAR | grep man2"
# man -wK CAP_ | grep man2 | sort | uniq
SYSCALLS = (

    # First, not a syscall yet very important to catch:

    ['system',
     'WARNING: system() may execute anything - ' + WARNING_NO_HINT,
     None],

    # Now for the actual syscalls
    # man pages section 2 - System calls (functions provided by the kernel)
    # All the value of this tool is in this list. Keep it tidy!

    # First the "open door" ones
    # (we don't care about the obsolete _syscallX)
    ['syscall',
     'WARNING: syscall() may be any syscall - ' + WARNING_NO_HINT,
     None],
    # The execve front-ends
    ['execl', WARNING_EXEC_FAMILY, None],
    ['execlp', WARNING_EXEC_FAMILY, None],
    ['execle', WARNING_EXEC_FAMILY, None],
    ['execv', WARNING_EXEC_FAMILY, None],
    ['execvp', WARNING_EXEC_FAMILY, None],
    ['execvpe', WARNING_EXEC_FAMILY, None],
    # execve itself and its brothers
    ['execve', WARNING_EXEC_FAMILY, None],
    ['execveat', WARNING_EXEC_FAMILY, None],
    ['fexecve', WARNING_EXEC_FAMILY, None],

    # Now for the other syscalls, in alphabetical order

    ['acct',
     'CAP_SYS_PACCT',
     None],
    ['adjtimex',
     None,
     'CAP_SYS_TIME'],
    ['bdflush',
     'CAP_SYS_ADMIN (Note: deprecated since Linux  2.6, this call does nothing.)',
     None],
    ['bind',
     None,
     'CAP_NET_BIND_SERVICE for port numbers less than 1024'],
    ['bpf',
     'CAP_SYS_ADMIN',
     None],
    ['capset',
     'CAP_SETPCAP',
     None],
    ['chmod',
     None,
     'CAP_FOWNER CAP_FSETID'],
    ['chown',
     'CAP_CHOWN',
     None],
    ['chroot',
     'CAP_SYS_CHROOT',
     None],
    ['clone',
     None,
     'CAP_SYS_ADMIN,  Linux < 3.8: CAP_SYS_ADMIN CAP_SETUID CAP_SETGID'],
    ['creat',
     None,
     'CAP_FOWNER'],
    ['create_module',
     'CAP_SYS_MODULE',
     None],
    ['delete_module',
     'CAP_SYS_MODULE',
     None],
    ['epoll_ctl',
     None,
     'CAP_BLOCK_SUSPEND'],
    ['fanotify_init',
     'CAP_SYS_ADMIN',
     None],
    ['fchmod',
     None,
     'CAP_FOWNER CAP_FSETID'],
    ['fchmodat',
     None,
     'CAP_FOWNER CAP_FSETID'],
    ['fchown',
     'CAP_CHOWN',
     None],
    ['fcntl',
     None,
     'CAP_LEASE CAP_SYS_RESOURCE CAP_FOWNER'],
    ['fcntl64',
     None,
     'CAP_LEASE CAP_SYS_RESOURCE CAP_FOWNER'],
    ['finit_module',
     'CAP_SYS_MODULE',
     None],
    ['getpriority',
     None,
     'CAP_SYS_NICE'],
    ['getrlimit',
     None,
     'CAP_SYS_RESOURCE'],
    ['init_module',
     'CAP_SYS_MODULE',
     None],
    ['ioctl',
     None,
     # SIOCSARP, SIOCDARP on AF_INET CAP_NET_ADMIN SIOCSPGRP on socket CAP_KILL TIOCSTI CAP_SYS_ADMIN
     'CAP_KILL CAP_SYS_ADMIN CAP_SYS_RAWIO CAP_SYS_RESOURCE CAP_SYS_TTY_CONFIG CAP_NET_ADMIN'],
    ['ioperm',
     None,
     "CAP_SYS_RAWIO"],
    ['iopl',
     None,
     'CAP_SYS_RAWIO'],
    ['ioprio_set',
     None,
     'CAP_SYS_ADMIN CAP_SYS_NICE'],
    ['kcmp',
     None,
     'CAP_SYS_PTRACE'],
    ['kexec_file_load',
     'CAP_SYS_BOOT',
     None],
    ['kexec_load',
     'CAP_SYS_BOOT',
     None],
    ['keyctl',
     None,
     'CAP_SYS_ADMIN'],
    ['kill',
     None,
     'CAP_KILL'],
    ['killpg',
     None,
     'CAP_KILL'],
    ['klogctl',
     None,
     'CAP_SYS_ADMIN (or better: CAP_SYSLOG)'],
    ['lchown',
     'CAP_CHOWN',
     None],
    ['lookup_dcookie',
     'CAP_SYS_ADMIN',
     None],
    ['madvise',
     None,
     'CAP_SYS_ADMIN'],
    ['mbind',
     None,
     'CAP_SYS_NICE'],
    ['migrate_pages',
     None,
     'CAP_SYS_NICE'],
    ['mknod',
     None,
     'CAP_MKNOD'],
    ['mknodat',
     None,
     'CAP_MKNOD'],
    ['mlock',
     None,
     'CAP_IPC_LOCK'],
    ['mlock2',
     None,
     'CAP_IPC_LOCK'],
    ['mlockall',
     None,
     'CAP_IPC_LOCK'],
    ['mount',
     'CAP_SYS_ADMIN',
     None],
    ['move_pages',
     None,
     'CAP_SYS_NICE'],
    ['msgctl',
     None,
     'CAP_SYS_RESOURCE CAP_IPC_OWNER CAP_SYS_ADMIN'],
    ['msgget',
     None,
     'CAP_IPC_OWNER'],
    ['msgrcv',
     None,
     'CAP_IPC_OWNER'],
    ['msgsnd',
     None,
     'CAP_IPC_OWNER'],
    ['munlock',
     None,
     'CAP_IPC_LOCK'],
    ['munlockall',
     None,
     'CAP_IPC_LOCK'],
    ['nfsservctl',
     'CAP_SYS_ADMIN (Note: Since Linux 3.1, this system call no longer exists.)',
     None],
    ['nice',
     None,
     'CAP_SYS_NICE'],
    ['open',
     None,
     'CAP_FOWNER'],
    ['openat',
     None,
     'CAP_FOWNER'],
    ['open_by_handle_at',
     'CAP_DAC_READ_SEARCH',
     None],
    ['pciconfig_read',
     'CAP_SYS_ADMIN',
     None],
    ['pciconfig_write',
     'CAP_SYS_ADMIN',
     None],
    ['perf_event_open',
     None,
     'CAP_SYS_ADMIN'],
    ['pivot_root',
     'CAP_SYS_ADMIN',
     None],
    ['prctl',
     None,
     'CAP_SETPCAP CAP_SYS_RESOURCE'],
    ['prlimit',
     None,
     'CAP_SYS_ADMIN CAP_SYS_RESOURCE'],
    ['process_vm_readv',
     None,
     'CAP_SYS_PTRACE'],
    ['process_vm_writev',
     None,
     'CAP_SYS_PTRACE'],
    ['ptrace',
     None,
     'CAP_SYS_ADMIN CAP_SYS_PTRACE'],
    ['quotactl',
     None,
     'CAP_SYS_ADMIN'],
    ['reboot',
     'CAP_SYS_BOOT',
     None],
    ['rename',
     None,
     'CAP_MKNOD CAP_FOWNER'],
    ['renameat',
     None,
     'CAP_MKNOD CAP_FOWNER'],
    ['renameat2',
     None,
     'CAP_MKNOD CAP_FOWNER'],
    ['rmdir',
     None,
     'CAP_FOWNER'],
    ['sched_setaffinity',
     None,
     'CAP_SYS_NICE'],
    ['sched_setattr',
     # Very broad: sched_setattr(2) does not mention specific capability,
     # yet may fail with errno "EPERM  The caller does not have appropriate privileges."
     # See sched(7). We'll take a conservative approach:
     None,
     'CAP_SYS_NICE'],
    ['sched_setparam',
     'CAP_SYS_NICE',
     None],
    ['sched_setscheduler',
     None,
     'CAP_SYS_NICE'],
    ['seccomp',
     None,
     'CAP_SYS_ADMIN'],
    ['semctl',
     None,
     'CAP_IPC_OWNER CAP_SYS_ADMIN'],
    ['semget',
     None,
     'CAP_IPC_OWNER'],
    ['semop',
     None,
     'CAP_IPC_OWNER'],
    ['semtimedop',
     None,
     'CAP_IPC_OWNER'],
    ['setdomainname',
     'CAP_SYS_ADMIN',
     None],
    ['seteuid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETUID',
     None],
    ['setfsgid',
     'CAP_SETGID',
     None],
    ['setfsuid',
     'CAP_SETUID',
     None],
    ['setgid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETGID',
     None],
    ['setgroups',
     'CAP_SETGID',
     None],
    ['sethostname',
     'CAP_SYS_ADMIN',
     None],
    ['setns',
     None,
     # difference between present time vs target namespace
     'CAP_SYS_CHROOT CAP_SYS_ADMIN'],
    ['setpriority',
     None,
     'CAP_SYS_NICE'],
    ['setreuid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETUID',
     None],
    ['setregid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETGID',
     None],
    ['setresuid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETUID',
     None],
    ['setresgid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETGID',
     None],
    ['setrlimit',
     None,
     'CAP_SYS_ADMIN CAP_SYS_RESOURCE'],
    ['setsockopt',
     None,
     'CAP_NET_ADMIN'],
    ['settimeofday',
     'CAP_SYS_TIME',
     None],
    ['setuid',
     # stricly speaking, this is not required - but for any meaningful use, it is
     'CAP_SETUID',
     None],
    ['set_robust_list',
     None,
     'CAP_SYS_PTRACE'],
    ['shmctl',
     None,
     'CAP_IPC_OWNER CAP_SYS_ADMIN'],
    ['shmget',
     None,
     'CAP_IPC_LOCK CAP_IPC_OWNER'],
    ['shmat',
     None,
     'CAP_IPC_OWNER'],
    ['shmdt',
     None,
     'CAP_IPC_OWNER'],
    ['sigqueue',
     None,
     'CAP_KILL'], # see kill(2)
    ['socket',
     None,
     # besides the documented RAW and PACKET sockets, also for AF_INET/SOCK_DGRAM (why???)
     'CAP_NET_RAW'],
    ['spu_create', # specific to PowerPC machines
     None,
     'CAP_SYS_NICE'],
    ['stime',
     'CAP_SYS_TIME',
     None],
    ['swapoff',
     'CAP_SYS_ADMIN',
     None],
    ['swapon',
     'CAP_SYS_ADMIN',
     None],
    ['umount',
     'CAP_SYS_ADMIN',
     None],
    ['umount2',
     'CAP_SYS_ADMIN',
     None],
    ['unlink',
     None,
     'CAP_FOWNER'],
    ['unlinkat',
     None,
     'CAP_FOWNER'],
    ['unshare',
     None,
     'see unshare(2) - often CAP_SYS_ADMIN, Linux kernel version dependant'],
    ['utime',
     None,
     'CAP_DAC_OVERRIDE CAP_FOWNER'],
    ['utimes',
     None,
     'CAP_DAC_OVERRIDE CAP_FOWNER'],
    ['vhangup',
     'CAP_SYS_TTY_CONFIG',
     None],
    ['vm86', # specific to 32-bit Intel processors
     None,
     'CAP_SYS_ADMIN'],
    ['vm86old', # specific to 32-bit Intel processors
     None,
     'CAP_SYS_ADMIN']

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

def syscall_listing(syscalls):
    for call in syscalls:
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
    # TODO warn if an ignored call is unknow, with suggestion to open github issue
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

    Syscall = collections.namedtuple('syscall', 'syscall require may_require regexp_pattern')
    syscalls = set()
    for call in SYSCALLS:
        syscalls.add(Syscall(call[0],
                             call[1],
                             call[2],
                             re.compile(r'\b' + call[0] + r'\b' + r'\s*\(')))

    if args.listing:
        syscall_listing(syscalls)
        sys.exit(0)

    ignored = []
    if args.ignore:
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
                for call in syscalls:
                    if call.syscall in ignored:
                        continue
                    if call.regexp_pattern.search(line):
                        print("%s:%d:%s"
                              % (fpath, linenum + 1, line), end='')
                        if call.require:
                            print(ColorCode.RED, end='')
                            print("'%s': %s"
                                  % (call.syscall, call.require))
                            print(ColorCode.NEUTRAL, end='')
                        if call.may_require:
                            print(ColorCode.ORANGE, end='')
                            print("'%s' may require %s"
                                  % (call.syscall, call.may_require))
                            print(ColorCode.NEUTRAL, end='')
    print("Done processing files in '%s'." % args.directory)

if __name__ == "__main__":
    main()
