module libssh.c_bindings.ctypes;

alias suseconds_t = long;
alias time_t = long;
alias c_long = long;


alias mode_t = uint;
alias uid_t = uint;
alias gid_t = uint;

enum FD_SETSIZE = 1024;
enum __NFDBITS = 8 * c_long.sizeof;

version(Posix) {
    struct timeval {
        time_t tv_sec;
        suseconds_t tv_usec;
    }

    struct fd_set {
        long[FD_SETSIZE / __NFDBITS] fds_bits;
    }
} else {
    public import core.sys.windows.winsock2 : timeval;
}
