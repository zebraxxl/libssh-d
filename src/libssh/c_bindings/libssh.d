module libssh.c_bindings.libssh;

import libssh.c_bindings.ctypes;

/* libssh version macros */
enum auto SSH_VERSION_INT(alias a, alias b, alias c) = (a << 16 | b << 8 | c);
enum auto SSH_VERSION_DOT(alias a, alias b, alias c) = 
    a.stringof ~ "." ~ b.stringof ~ "." ~ c.stringof;
enum auto SSH_VERSION(alias a, alias b, alias c) = SSH_VERSION_DOT!(a, b, c);

/* libssh version */
enum auto LIBSSH_VERSION_MAJOR  = 0;
enum auto LIBSSH_VERSION_MINOR  = 7;
enum auto LIBSSH_VERSION_MICRO  = 3;

enum auto LIBSSH_VERSION_INT = SSH_VERSION_INT!(
    LIBSSH_VERSION_MAJOR, 
    LIBSSH_VERSION_MINOR, 
    LIBSSH_VERSION_MICRO);
enum auto LIBSSH_VERSION = SSH_VERSION!(
    LIBSSH_VERSION_MAJOR, 
    LIBSSH_VERSION_MINOR, 
    LIBSSH_VERSION_MICRO);

struct ssh_counter_struct {
    ulong in_bytes;
    ulong out_bytes;
    ulong in_packets;
    ulong out_packets;
}
alias ssh_counter = ssh_counter_struct*;

struct ssh_agent_struct { }
struct ssh_buffer_struct { }
struct ssh_channel_struct { }
struct ssh_message_struct { }
struct ssh_pcap_file_struct { }
struct ssh_key_struct { }
struct ssh_scp_struct { }
struct ssh_session_struct { }
struct ssh_string_struct { }
struct ssh_event_struct { }
alias ssh_agent = ssh_agent_struct*;
alias ssh_buffer = ssh_buffer_struct*;
alias ssh_channel = ssh_channel_struct*;
alias ssh_message = ssh_message_struct*;
alias ssh_pcap_file = ssh_pcap_file_struct*;
alias ssh_key = ssh_key_struct*;
alias ssh_scp = ssh_scp_struct*;
alias ssh_session = ssh_session_struct*;
alias ssh_string = ssh_string_struct*;
alias ssh_event = ssh_event_struct*;
alias ssh_gssapi_creds = void*;

/* Socket type */
// From std.socket
version(Windows) {
    import std.socket;
    alias socket_t = SOCKET;
} else version(Posix) {
    alias socket_t = int;
} else {
    static assert(0);
}

enum socket_t SSH_INVALID_SOCKET = cast(socket_t) -1;

/* the offsets of methods */
enum ssh_kex_types_e {
    SSH_KEX=0,
    SSH_HOSTKEYS,
    SSH_CRYPT_C_S,
    SSH_CRYPT_S_C,
    SSH_MAC_C_S,
    SSH_MAC_S_C,
    SSH_COMP_C_S,
    SSH_COMP_S_C,
    SSH_LANG_C_S,
    SSH_LANG_S_C,
}

enum auto SSH_CRYPT = 2;
enum auto SSH_MAC = 3;
enum auto SSH_COMP = 4;
enum auto SSH_LANG = 5;

enum ssh_auth_e {
    SSH_AUTH_SUCCESS=0,
    SSH_AUTH_DENIED,
    SSH_AUTH_PARTIAL,
    SSH_AUTH_INFO,
    SSH_AUTH_AGAIN,
    SSH_AUTH_ERROR=-1
};

/* auth flags */
enum auto SSH_AUTH_METHOD_UNKNOWN = 0;
enum auto SSH_AUTH_METHOD_NONE = 0x0001;
enum auto SSH_AUTH_METHOD_PASSWORD = 0x0002;
enum auto SSH_AUTH_METHOD_PUBLICKEY = 0x0004;
enum auto SSH_AUTH_METHOD_HOSTBASED = 0x0008;
enum auto SSH_AUTH_METHOD_INTERACTIVE = 0x0010;
enum auto SSH_AUTH_METHOD_GSSAPI_MIC = 0x0020;

/* messages */
enum ssh_requests_e {
    SSH_REQUEST_AUTH=1,
    SSH_REQUEST_CHANNEL_OPEN,
    SSH_REQUEST_CHANNEL,
    SSH_REQUEST_SERVICE,
    SSH_REQUEST_GLOBAL
};

enum ssh_channel_type_e {
    SSH_CHANNEL_UNKNOWN=0,
    SSH_CHANNEL_SESSION,
    SSH_CHANNEL_DIRECT_TCPIP,
    SSH_CHANNEL_FORWARDED_TCPIP,
    SSH_CHANNEL_X11
};

enum ssh_channel_requests_e {
    SSH_CHANNEL_REQUEST_UNKNOWN=0,
    SSH_CHANNEL_REQUEST_PTY,
    SSH_CHANNEL_REQUEST_EXEC,
    SSH_CHANNEL_REQUEST_SHELL,
    SSH_CHANNEL_REQUEST_ENV,
    SSH_CHANNEL_REQUEST_SUBSYSTEM,
    SSH_CHANNEL_REQUEST_WINDOW_CHANGE,
    SSH_CHANNEL_REQUEST_X11
};

enum ssh_global_requests_e {
    SSH_GLOBAL_REQUEST_UNKNOWN=0,
    SSH_GLOBAL_REQUEST_TCPIP_FORWARD,
    SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD,
};

enum ssh_publickey_state_e {
    SSH_PUBLICKEY_STATE_ERROR=-1,
    SSH_PUBLICKEY_STATE_NONE=0,
    SSH_PUBLICKEY_STATE_VALID=1,
    SSH_PUBLICKEY_STATE_WRONG=2
};

/* Status flags */
/** Socket is closed */
enum auto SSH_CLOSED = 0x01;
/** Reading to socket won't block */
enum auto SSH_READ_PENDING = 0x02;
/** Session was closed due to an error */
enum auto SSH_CLOSED_ERROR = 0x04;
/** Output buffer not empty */
enum auto SSH_WRITE_PENDING = 0x08;

enum ssh_server_known_e {
    SSH_SERVER_ERROR=-1,
    SSH_SERVER_NOT_KNOWN=0,
    SSH_SERVER_KNOWN_OK,
    SSH_SERVER_KNOWN_CHANGED,
    SSH_SERVER_FOUND_OTHER,
    SSH_SERVER_FILE_NOT_FOUND
};

enum auto MD5_DIGEST_LEN = 16;

/* errors */

enum ssh_error_types_e {
    SSH_NO_ERROR=0,
    SSH_REQUEST_DENIED,
    SSH_FATAL,
    SSH_EINTR
};

/* some types for keys */
enum ssh_keytypes_e{
    SSH_KEYTYPE_UNKNOWN=0,
    SSH_KEYTYPE_DSS=1,
    SSH_KEYTYPE_RSA,
    SSH_KEYTYPE_RSA1,
    SSH_KEYTYPE_ECDSA,
    SSH_KEYTYPE_ED25519
};

enum ssh_keycmp_e {
    SSH_KEY_CMP_PUBLIC = 0,
    SSH_KEY_CMP_PRIVATE
};

/* Error return codes */
enum auto SSH_OK = 0;     /* No error */
enum auto SSH_ERROR = -1; /* Error of some kind */
enum auto SSH_AGAIN = -2; /* The nonblocking call must be repeated */
enum auto SSH_EOF = -127; /* We have already a eof */

/**
 * @addtogroup libssh_log
 *
 * @{
 */

enum {
    /** No logging at all
     */
    SSH_LOG_NOLOG=0,
    /** Only warnings
     */
    SSH_LOG_WARNING,
    /** High level protocol information
     */
    SSH_LOG_PROTOCOL,
    /** Lower level protocol infomations, packet level
     */
    SSH_LOG_PACKET,
    /** Every function path
     */
    SSH_LOG_FUNCTIONS
};
/** @} */
enum auto SSH_LOG_RARE = SSH_LOG_WARNING;

/**
 * @name Logging levels
 *
 * @brief Debug levels for logging.
 * @{
 */

/** No logging at all */
enum auto SSH_LOG_NONE = 0;
/** Show only warnings */
enum auto SSH_LOG_WARN = 1;
/** Get some information what's going on */
enum auto SSH_LOG_INFO = 2;
/** Get detailed debuging information **/
enum auto SSH_LOG_DEBUG = 3;
/** Get trace output, packet information, ... */
enum auto SSH_LOG_TRACE = 4;

/** @} */

enum ssh_options_e {
    SSH_OPTIONS_HOST,
    SSH_OPTIONS_PORT,
    SSH_OPTIONS_PORT_STR,
    SSH_OPTIONS_FD,
    SSH_OPTIONS_USER,
    SSH_OPTIONS_SSH_DIR,
    SSH_OPTIONS_IDENTITY,
    SSH_OPTIONS_ADD_IDENTITY,
    SSH_OPTIONS_KNOWNHOSTS,
    SSH_OPTIONS_TIMEOUT,
    SSH_OPTIONS_TIMEOUT_USEC,
    SSH_OPTIONS_SSH1,
    SSH_OPTIONS_SSH2,
    SSH_OPTIONS_LOG_VERBOSITY,
    SSH_OPTIONS_LOG_VERBOSITY_STR,
    SSH_OPTIONS_CIPHERS_C_S,
    SSH_OPTIONS_CIPHERS_S_C,
    SSH_OPTIONS_COMPRESSION_C_S,
    SSH_OPTIONS_COMPRESSION_S_C,
    SSH_OPTIONS_PROXYCOMMAND,
    SSH_OPTIONS_BINDADDR,
    SSH_OPTIONS_STRICTHOSTKEYCHECK,
    SSH_OPTIONS_COMPRESSION,
    SSH_OPTIONS_COMPRESSION_LEVEL,
    SSH_OPTIONS_KEY_EXCHANGE,
    SSH_OPTIONS_HOSTKEYS,
    SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
    SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
    SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
    SSH_OPTIONS_HMAC_C_S,
    SSH_OPTIONS_HMAC_S_C,
};

enum {
    /** Code is going to write/create remote files */
    SSH_SCP_WRITE,
    /** Code is going to read remote files */
    SSH_SCP_READ,
    SSH_SCP_RECURSIVE=0x10
};

enum ssh_scp_request_types {
    /** A new directory is going to be pulled */
    SSH_SCP_REQUEST_NEWDIR=1,
    /** A new file is going to be pulled */
    SSH_SCP_REQUEST_NEWFILE,
    /** End of requests */
    SSH_SCP_REQUEST_EOF,
    /** End of directory */
    SSH_SCP_REQUEST_ENDDIR,
    /** Warning received */
    SSH_SCP_REQUEST_WARNING
};

extern (C) {
    int ssh_blocking_flush(ssh_session session, int timeout);
    ssh_channel ssh_channel_accept_x11(ssh_channel channel, int timeout_ms);
    int ssh_channel_change_pty_size(ssh_channel channel,int cols,int rows);
    int ssh_channel_close(ssh_channel channel);
    void ssh_channel_free(ssh_channel channel);
    int ssh_channel_get_exit_status(ssh_channel channel);
    ssh_session ssh_channel_get_session(ssh_channel channel);
    int ssh_channel_is_closed(ssh_channel channel);
    int ssh_channel_is_eof(ssh_channel channel);
    int ssh_channel_is_open(ssh_channel channel);
    ssh_channel ssh_channel_new(ssh_session session);
    int ssh_channel_open_auth_agent(ssh_channel channel);
    int ssh_channel_open_forward(ssh_channel channel, const char *remotehost,
        int remoteport, const char *sourcehost, int localport);
    int ssh_channel_open_session(ssh_channel channel);
    int ssh_channel_open_x11(ssh_channel channel, const char *orig_addr, int orig_port);
    int ssh_channel_poll(ssh_channel channel, int is_stderr);
    int ssh_channel_poll_timeout(ssh_channel channel, int timeout, int is_stderr);
    int ssh_channel_read(ssh_channel channel, void *dest, uint count, int is_stderr);
    int ssh_channel_read_timeout(ssh_channel channel, void *dest, uint count, int is_stderr, 
        int timeout_ms);
    int ssh_channel_read_nonblocking(ssh_channel channel, void *dest, uint count,
        int is_stderr);
    int ssh_channel_request_env(ssh_channel channel, const char *name, const char *value);
    int ssh_channel_request_exec(ssh_channel channel, const char *cmd);
    int ssh_channel_request_pty(ssh_channel channel);
    int ssh_channel_request_pty_size(ssh_channel channel, const char *term,
        int cols, int rows);
    int ssh_channel_request_shell(ssh_channel channel);
    int ssh_channel_request_send_signal(ssh_channel channel, const char *signum);
    int ssh_channel_request_sftp(ssh_channel channel);
    int ssh_channel_request_subsystem(ssh_channel channel, const char *subsystem);
    int ssh_channel_request_x11(ssh_channel channel, int single_connection, const char *protocol,
        const char *cookie, int screen_number);
    int ssh_channel_send_eof(ssh_channel channel);
    int ssh_channel_select(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, 
        timeval* timeout);
    void ssh_channel_set_blocking(ssh_channel channel, int blocking);
    void ssh_channel_set_counter(ssh_channel channel,
        ssh_counter counter);
    int ssh_channel_write(ssh_channel channel, const void *data, uint len);
    uint ssh_channel_window_size(ssh_channel channel);

    char *ssh_basename (const char *path);
    void ssh_clean_pubkey_hash(ubyte **hash);
    int ssh_connect(ssh_session session);
    const(char)* ssh_copyright();
    void ssh_disconnect(ssh_session session);
    char *ssh_dirname (const char *path);
    int ssh_finalize();

    /* REVERSE PORT FORWARDING */
    ssh_channel ssh_channel_accept_forward(ssh_session session,
        int timeout_ms,
        int *destination_port);
    int ssh_channel_cancel_forward(ssh_session session,
        const char *address,
        int port);
    int ssh_channel_listen_forward(ssh_session session,
        const char *address,
        int port,
        int *bound_port);

    void ssh_free(ssh_session session);
    const(char) *ssh_get_disconnect_message(ssh_session session);
    const(char) *ssh_get_error(void *error);
    int ssh_get_error_code(void *error);
    socket_t ssh_get_fd(ssh_session session);
    char *ssh_get_hexa(const ubyte* what, size_t len);
    char *ssh_get_issue_banner(ssh_session session);
    int ssh_get_openssh_version(ssh_session session);

    int ssh_get_publickey(ssh_session session, ssh_key *key);

    enum ssh_publickey_hash_type {
        SSH_PUBLICKEY_HASH_SHA1,
        SSH_PUBLICKEY_HASH_MD5
    };

    int ssh_get_publickey_hash(const ssh_key key, ssh_publickey_hash_type type,
        ubyte **hash, size_t *hlen);

    /* DEPRECATED FUNCTIONS */
    deprecated int ssh_get_pubkey_hash(ssh_session session, ubyte **hash);
    deprecated ssh_channel ssh_forward_accept(ssh_session session, int timeout_ms);
    deprecated int ssh_forward_cancel(ssh_session session, const char *address, int port);
    deprecated int ssh_forward_listen(ssh_session session, const char *address, int port, 
        int *bound_port);

    int ssh_get_random(void *where,int len,int strong);
    int ssh_get_version(ssh_session session);
    int ssh_get_status(ssh_session session);
    int ssh_get_poll_flags(ssh_session session);
    int ssh_init();
    int ssh_is_blocking(ssh_session session);
    int ssh_is_connected(ssh_session session);
    int ssh_is_server_known(ssh_session session);

    /* LOGGING */
    int ssh_set_log_level(int level);
    int ssh_get_log_level();
    void *ssh_get_log_userdata();
    int ssh_set_log_userdata(void *data);
    void _ssh_log(int verbosity, const char *function_, const char *format, ...);
    /* legacy */
    deprecated void ssh_log(ssh_session session, int prioriry, const char *format, ...);

    ssh_channel ssh_message_channel_request_open_reply_accept(ssh_message msg);
    int ssh_message_channel_request_reply_success(ssh_message msg);
    void ssh_message_free(ssh_message msg);
    ssh_message ssh_message_get(ssh_session session);
    int ssh_message_subtype(ssh_message msg);
    int ssh_message_type(ssh_message msg);
    int ssh_mkdir (const char *pathname, mode_t mode);
    ssh_session ssh_new();

    int ssh_options_copy(ssh_session src, ssh_session *dest);
    int ssh_options_getopt(ssh_session session, int *argcptr, char **argv);
    int ssh_options_parse_config(ssh_session session, const char *filename);
    int ssh_options_set(ssh_session session, ssh_options_e type,
        const void *value);
    int ssh_options_get(ssh_session session, ssh_options_e type,
        char **value);
    int ssh_options_get_port(ssh_session session, uint * port_target);
    int ssh_pcap_file_close(ssh_pcap_file pcap);
    void ssh_pcap_file_free(ssh_pcap_file pcap);
    ssh_pcap_file ssh_pcap_file_new();
    int ssh_pcap_file_open(ssh_pcap_file pcap, const char *filename);

    /**
     * @brief SSH authentication callback.
     *
     * @param prompt        Prompt to be displayed.
     * @param buf           Buffer to save the password. You should null-terminate it.
     * @param len           Length of the buffer.
     * @param echo          Enable or disable the echo of what you type.
     * @param verify        Should the password be verified?
     * @param userdata      Userdata to be passed to the callback function. Useful
     *                      for GUI applications.
     *
     * @return              0 on success, < 0 on error.
     */
    alias ssh_auth_callback = extern(C) int function(const char *prompt, char *buf, size_t len,
        int echo, int verify, void *userdata);

    ssh_key ssh_key_new();
    void ssh_key_free (ssh_key key);
    ssh_keytypes_e ssh_key_type(const ssh_key key);
    const(char) *ssh_key_type_to_char(ssh_keytypes_e type);
    ssh_keytypes_e ssh_key_type_from_name(const char *name);
    int ssh_key_is_public(const ssh_key k);
    int ssh_key_is_private(const ssh_key k);
    int ssh_key_cmp(const ssh_key k1,
        const ssh_key k2,
        ssh_keycmp_e what);
    
    int ssh_pki_generate(ssh_keytypes_e type, int parameter,
        ssh_key *pkey);
    int ssh_pki_import_privkey_base64(const char *b64_key,
        const char *passphrase,
        ssh_auth_callback auth_fn,
        void *auth_data,
        ssh_key *pkey);
    int ssh_pki_import_privkey_file(const char *filename,
        const char *passphrase,
        ssh_auth_callback auth_fn,
        void *auth_data,
        ssh_key *pkey);
    int ssh_pki_export_privkey_file(const ssh_key privkey,
        const char *passphrase,
        ssh_auth_callback auth_fn,
        void *auth_data,
        const char *filename);
    
    int ssh_pki_import_pubkey_base64(const char *b64_key,
        ssh_keytypes_e type,
        ssh_key *pkey);
    int ssh_pki_import_pubkey_file(const char *filename,
        ssh_key *pkey);
    
    int ssh_pki_export_privkey_to_pubkey(const ssh_key privkey,
        ssh_key *pkey);
    int ssh_pki_export_pubkey_base64(const ssh_key key,
        char **b64_key);
    int ssh_pki_export_pubkey_file(const ssh_key key,
        const char *filename);
    
    const(char) *ssh_pki_key_ecdsa_name(const ssh_key key);
    
    void ssh_print_hexa(const char *descr, const ubyte *what, size_t len);
    int ssh_send_ignore (ssh_session session, const char *data);
    int ssh_send_debug (ssh_session session, const char *message, int always_display);
    void ssh_gssapi_set_creds(ssh_session session, const ssh_gssapi_creds creds);
    int ssh_scp_accept_request(ssh_scp scp);
    int ssh_scp_close(ssh_scp scp);
    int ssh_scp_deny_request(ssh_scp scp, const char *reason);
    void ssh_scp_free(ssh_scp scp);
    int ssh_scp_init(ssh_scp scp);
    int ssh_scp_leave_directory(ssh_scp scp);
    ssh_scp ssh_scp_new(ssh_session session, int mode, const char *location);
    int ssh_scp_pull_request(ssh_scp scp);
    int ssh_scp_push_directory(ssh_scp scp, const char *dirname, int mode);
    int ssh_scp_push_file(ssh_scp scp, const char *filename, size_t size, int perms);
    int ssh_scp_push_file64(ssh_scp scp, const char *filename, ulong size, int perms);
    int ssh_scp_read(ssh_scp scp, void *buffer, size_t size);
    const(char) *ssh_scp_request_get_filename(ssh_scp scp);
    int ssh_scp_request_get_permissions(ssh_scp scp);
    size_t ssh_scp_request_get_size(ssh_scp scp);
    ulong ssh_scp_request_get_size64(ssh_scp scp);
    const(char) *ssh_scp_request_get_warning(ssh_scp scp);
    int ssh_scp_write(ssh_scp scp, const void *buffer, size_t len);
    int ssh_select(ssh_channel *channels, ssh_channel *outchannels, socket_t maxfd,
        fd_set *readfds, timeval *timeout);
    int ssh_service_request(ssh_session session, const char *service);
    int ssh_set_agent_channel(ssh_session session, ssh_channel channel);
    int ssh_set_agent_socket(ssh_session session, socket_t fd);
    void ssh_set_blocking(ssh_session session, int blocking);
    void ssh_set_counters(ssh_session session, ssh_counter scounter,
        ssh_counter rcounter);
    void ssh_set_fd_except(ssh_session session);
    void ssh_set_fd_toread(ssh_session session);
    void ssh_set_fd_towrite(ssh_session session);
    void ssh_silent_disconnect(ssh_session session);
    int ssh_set_pcap_file(ssh_session session, ssh_pcap_file pcapfile);
    
    /* USERAUTH */
    int ssh_userauth_none(ssh_session session, const char *username);
    int ssh_userauth_list(ssh_session session, const char *username);
    int ssh_userauth_try_publickey(ssh_session session,
        const char *username,
        const ssh_key pubkey);
    int ssh_userauth_publickey(ssh_session session,
        const char *username,
        const ssh_key privkey);

    version(Windows) { } else {
        int ssh_userauth_agent(ssh_session session,
            const char *username);
    }

    int ssh_userauth_publickey_auto(ssh_session session,
        const char *username,
        const char *passphrase);
    int ssh_userauth_password(ssh_session session,
        const char *username,
        const char *password);
    
    int ssh_userauth_kbdint(ssh_session session, const char *user, const char *submethods);
    const(char) *ssh_userauth_kbdint_getinstruction(ssh_session session);
    const(char) *ssh_userauth_kbdint_getname(ssh_session session);
    int ssh_userauth_kbdint_getnprompts(ssh_session session);
    const(char) *ssh_userauth_kbdint_getprompt(ssh_session session, uint i, char *echo);
    int ssh_userauth_kbdint_getnanswers(ssh_session session);
    const(char) *ssh_userauth_kbdint_getanswer(ssh_session session, uint i);
    int ssh_userauth_kbdint_setanswer(ssh_session session, uint i,
        const char *answer);
    int ssh_userauth_gssapi(ssh_session session);
    const(char) *ssh_version(int req_version);
    int ssh_write_knownhost(ssh_session session);
    
    void ssh_string_burn(ssh_string str);
    ssh_string ssh_string_copy(ssh_string str);
    void *ssh_string_data(ssh_string str);
    int ssh_string_fill(ssh_string str, const void *data, size_t len);
    void ssh_string_free(ssh_string str);
    ssh_string ssh_string_from_char(const char *what);
    size_t ssh_string_len(ssh_string str);
    ssh_string ssh_string_new(size_t size);
    const(char) *ssh_string_get_char(ssh_string str);
    char *ssh_string_to_char(ssh_string str);
    void ssh_string_free_char(char *s);
    
    int ssh_getpass(const char *prompt, char *buf, size_t len, int echo,
        int verify);
    

    alias ssh_event_callback = extern(C) int function(socket_t fd, int revents, void *userdata);
    
    ssh_event ssh_event_new();
    int ssh_event_add_fd(ssh_event event, socket_t fd, short events,
        ssh_event_callback cb, void *userdata);
    int ssh_event_add_session(ssh_event event, ssh_session session);
    int ssh_event_dopoll(ssh_event event, int timeout);
    int ssh_event_remove_fd(ssh_event event, socket_t fd);
    int ssh_event_remove_session(ssh_event event, ssh_session session);
    void ssh_event_free(ssh_event event);
    const(char)* ssh_get_clientbanner(ssh_session session);
    const(char)* ssh_get_serverbanner(ssh_session session);
    const(char)* ssh_get_kex_algo(ssh_session session);
    const(char)* ssh_get_cipher_in(ssh_session session);
    const(char)* ssh_get_cipher_out(ssh_session session);
    const(char)* ssh_get_hmac_in(ssh_session session);
    const(char)* ssh_get_hmac_out(ssh_session session);
}
