module libssh.c_bindings.legacy;

import libssh.c_bindings.libssh;
import libssh.c_bindings.ctypes;

struct ssh_private_key_struct { }
struct ssh_public_key_struct { }
alias ssh_private_key = ssh_private_key_struct*;
alias ssh_public_key = ssh_public_key_struct*;

extern (C) {
    int ssh_auth_list(ssh_session session);
    int ssh_userauth_offer_pubkey(ssh_session session, const char *username, int type, 
        ssh_string publickey);
    int ssh_userauth_pubkey(ssh_session session, const char *username, ssh_string publickey, 
        ssh_private_key privatekey);

    version (Windows) {
        int ssh_userauth_agent_pubkey(ssh_session session, const char *username,
            ssh_public_key publickey);
    }

    int ssh_userauth_autopubkey(ssh_session session, const char *passphrase);
    int ssh_userauth_privatekey_file(ssh_session session, const char *username,
        const char *filename, const char *passphrase);

    deprecated {
        void buffer_free(ssh_buffer buffer);
        void *buffer_get(ssh_buffer buffer);
        uint buffer_get_len(ssh_buffer buffer);
        ssh_buffer buffer_new();
        
        ssh_channel channel_accept_x11(ssh_channel channel, int timeout_ms);
        int channel_change_pty_size(ssh_channel channel,int cols,int rows);
        ssh_channel channel_forward_accept(ssh_session session, int timeout_ms);
        int channel_close(ssh_channel channel);
        int channel_forward_cancel(ssh_session session, const char *address, int port);
        int channel_forward_listen(ssh_session session, const char *address, int port, 
            int *bound_port);
        void channel_free(ssh_channel channel);
        int channel_get_exit_status(ssh_channel channel);
        ssh_session channel_get_session(ssh_channel channel);
        int channel_is_closed(ssh_channel channel);
        int channel_is_eof(ssh_channel channel);
        int channel_is_open(ssh_channel channel);
        ssh_channel channel_new(ssh_session session);
        int channel_open_forward(ssh_channel channel, const char *remotehost,
            int remoteport, const char *sourcehost, int localport);
        int channel_open_session(ssh_channel channel);
        int channel_poll(ssh_channel channel, int is_stderr);
        int channel_read(ssh_channel channel, void *dest, uint count, int is_stderr);
        
        int channel_read_buffer(ssh_channel channel, ssh_buffer buffer, uint count,
            int is_stderr);
        
        int channel_read_nonblocking(ssh_channel channel, void *dest, uint count,
            int is_stderr);
        int channel_request_env(ssh_channel channel, const char *name, const char *value);
        int channel_request_exec(ssh_channel channel, const char *cmd);
        int channel_request_pty(ssh_channel channel);
        int channel_request_pty_size(ssh_channel channel, const char *term,
            int cols, int rows);
        int channel_request_shell(ssh_channel channel);
        int channel_request_send_signal(ssh_channel channel, const char *signum);
        int channel_request_sftp(ssh_channel channel);
        int channel_request_subsystem(ssh_channel channel, const char *subsystem);
        int channel_request_x11(ssh_channel channel, int single_connection, const char *protocol,
            const char *cookie, int screen_number);
        int channel_send_eof(ssh_channel channel);
        int channel_select(ssh_channel *readchans, ssh_channel *writechans, ssh_channel *exceptchans, 
            timeval * timeout);
        void channel_set_blocking(ssh_channel channel, int blocking);
        int channel_write(ssh_channel channel, const void *data, uint len);
    }

    void privatekey_free(ssh_private_key prv);
    ssh_private_key privatekey_from_file(ssh_session session, const char *filename,
        int type, const char *passphrase);
    void publickey_free(ssh_public_key key);
    int ssh_publickey_to_file(ssh_session session, const char *file,
        ssh_string pubkey, int type);
    ssh_string publickey_from_file(ssh_session session, const char *filename,
        int *type);
    ssh_public_key publickey_from_privatekey(ssh_private_key prv);
    ssh_string publickey_to_string(ssh_public_key key);
    int ssh_try_publickey_from_file(ssh_session session, const char *keyfile,
        ssh_string *publickey, int *type);
    enum ssh_keytypes_e ssh_privatekey_type(ssh_private_key privatekey);
    
    ssh_string ssh_get_pubkey(ssh_session session);
    
    ssh_message ssh_message_retrieve(ssh_session session, uint packettype);
    ssh_public_key ssh_message_auth_publickey(ssh_message msg);

    deprecated {
        void string_burn(ssh_string str);
        ssh_string string_copy(ssh_string str);
        void *string_data(ssh_string str);
        int string_fill(ssh_string str, const void *data, size_t len);
        void string_free(ssh_string str);
        ssh_string string_from_char(const char *what);
        size_t string_len(ssh_string str);
        ssh_string string_new(size_t size);
        char *string_to_char(ssh_string str);
    }
}
