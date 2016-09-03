module libssh.c_bindings.ctypes;

import core.sys.posix.sys.types;
import core.sys.posix.sys.time;
import core.sys.posix.sys.select;

alias timeval = core.sys.posix.sys.time.timeval;
alias mode_t = core.sys.posix.sys.types.mode_t;
alias fd_set = core.sys.posix.sys.select.fd_set;
alias uid_t = core.sys.posix.sys.types.uid_t;
alias gid_t = core.sys.posix.sys.types.gid_t;
