module libssh.c_bindings.poll;

version (Windows) {
    enum auto POLLRDNORM = 0x0100;
    enum auto POLLRDBAND = 0x0200;
    enum auto POLLIN     = POLLRDNORM | POLLRDBAND;
    enum auto POLLPRI    = 0x0400;

    enum auto POLLWRNORM = 0x0010;
    enum auto POLLOUT    = POLLWRNORM;
    enum auto POLLWRBAND = 0x0020;

    enum auto POLLERR    = 0x0001;
    enum auto POLLHUP    = 0x0002;
    enum auto POLLNVAL   = 0x0004;
} else {
    enum auto POLLIN   = 0x001;  /* There is data to read.  */
    enum auto POLLPRI  = 0x002;  /* There is urgent data to read.  */
    enum auto POLLOUT  = 0x004;  /* Writing now will not block.  */

    enum auto POLLERR  = 0x008;  /* Error condition.  */
    enum auto POLLHUP  = 0x010;  /* Hung up.  */
    enum auto POLLNVAL = 0x020;  /* Invalid polling request.  */

    enum auto POLLRDNORM =  0x040; /* mapped to read fds_set */
    enum auto POLLRDBAND =  0x080; /* mapped to exception fds_set */
    enum auto POLLWRNORM =  0x100; /* mapped to write fds_set */
    enum auto POLLWRBAND =  0x200; /* mapped to write fds_set */
}
