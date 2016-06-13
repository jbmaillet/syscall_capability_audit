# syscall_capability_audit

Static code analysis tool, listing Linux system calls capability requirements. 

## Usage

	$ ./syscall_capability_audit.py
	usage: syscall_capability_audit.py [-h] [-d topleveldir] [-l] [-i ig1,ig2,...]
	                                   [-v]

	Scan source code for syscalls requiring capabilities.

	optional arguments:
	  -h, --help            show this help message and exit
	  -d topleveldir, --directory topleveldir
	                        Top level source code directory.
	  -l, --listing         List managed syscalls and corresponding capabilities.
	  -m, --mandatory_only  Output only syscalls for which a capability is
	                        mandatory. Note that this will also include system(3),
	                        syscall(2) and the exec*(2) family, for which no
	                        capability is strictly speaking mandatory, but which
	                        always require careful inspection. This will also
	                        include calls such as to set*uid(2) and set*gid(2),
	                        which for any meaningful purpose require capabilities
	                        too.
	  -i ig1,ig2,..., --ignore ig1,ig2,...
	                        Comma separated list of syscalls to ignore This may be
	                        useful if source code uses custom functions or methods
	                        named the same way as syscalls, or if you prefer not
	                        to get output for potentialy noisy syscalls such as
	                        open(2), socket(2), or ioctl(2). system(3), syscall(2)
	                        and the exec*(2) family cannot be ignored.
	  -v, --verbose         Increase processing verbosity.

## About capabilities

http://man7.org/linux/man-pages/man7/capabilities.7.html
