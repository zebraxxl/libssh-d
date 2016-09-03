module libssh.server;

import std.string;

import libssh.c_bindings.libssh;
import libssh.c_bindings.callbacks;
import libssh.c_bindings.server;
import libssh.errors;
import libssh.utils;
import libssh.session;
import libssh.channel;
import libssh.message;

enum BindOption : int {
    BindAddr = ssh_bind_options_e.SSH_BIND_OPTIONS_BINDADDR,
    BindPort = ssh_bind_options_e.SSH_BIND_OPTIONS_BINDPORT,
    BindPortStr = ssh_bind_options_e.SSH_BIND_OPTIONS_BINDPORT_STR,
    Hostkey = ssh_bind_options_e.SSH_BIND_OPTIONS_HOSTKEY,
    DsaKey = ssh_bind_options_e.SSH_BIND_OPTIONS_DSAKEY,
    RsaKey = ssh_bind_options_e.SSH_BIND_OPTIONS_RSAKEY,
    Banner = ssh_bind_options_e.SSH_BIND_OPTIONS_BANNER,
    LogVerbosity = ssh_bind_options_e.SSH_BIND_OPTIONS_LOG_VERBOSITY,
    LogVerbosityStr = ssh_bind_options_e.SSH_BIND_OPTIONS_LOG_VERBOSITY_STR,
    EcdsaKey = ssh_bind_options_e.SSH_BIND_OPTIONS_ECDSAKEY
}

class SSHBind : Disposable {
    alias OnIncomingConnectionCallback = void delegate();

    @property OnIncomingConnectionCallback onIncomingConnectionCallback() {
        return this._onIncomingConnectionCallback;
    }

    @property void onIncomingConnectionCallback(OnIncomingConnectionCallback cb) {
        this._onIncomingConnectionCallback = cb;
        if (cb is null) {
            this._callbacks.incoming_connection = null;
        } else {
            this._callbacks.incoming_connection = &nativeOnIncomingConnection;
        }
        ssh_bind_set_callbacks(this._bind, &this._callbacks, cast(void*) this);
    }

    @property void blocking(bool v) {
        ssh_bind_set_blocking(this._bind, v ? 1 : 0);
    }

    @property socket_t fd() {
        return ssh_bind_get_fd(this._bind);
    }

    @property void fd(socket_t fd) {
        ssh_bind_set_fd(this._bind, fd);
    }


    @property void hostkey(string v) {
        this.setOption(BindOption.Hostkey, v);
    }

    @property void bindAddress(string v) {
        this.setOption(BindOption.BindAddr, v);
    }

    @property void bindPort(ushort v) {
        this.setOption(BindOption.BindPort, cast(uint) v);
    }

    @property void bindPortStr(string v) {
        this.setOption(BindOption.BindPortStr, v);
    }

    @property void logVerbosity(LogVerbosity v) {
        this.setOption(BindOption.LogVerbosity, cast(int) v);
    }

    @property void logVerbosityStr(string v) {
        this.setOption(BindOption.LogVerbosityStr, v);
    }

    @property void dsaKey(string v) {
        this.setOption(BindOption.DsaKey, v);
    }

    @property void rsaKey(string v) {
        this.setOption(BindOption.RsaKey, v);
    }

    @property void ecdsaKey(string v) {
        this.setOption(BindOption.EcdsaKey, v);
    }

    @property void banner(string v) {
        this.setOption(BindOption.Banner, v);
    }


    SSHSession accept() {
        auto session = new SSHSession();
        if (session is null) {
            throw new SSHException("Error while preallocating session");
        }
        scope(failure) session.dispose();

        return this.accept(session);
    }

    SSHSession accept(SSHSession session) {
        auto rc = ssh_bind_accept(this._bind, session._session);
        checkForRCError(rc, this._bind);
        return session;
    }

    SSHSession accept(socket_t fd) {
        auto session = new SSHSession();
        if (session is null) {
            throw new SSHException("Error while preallocating session");
        }
        scope(failure) session.dispose();

        return this.accept(session, fd);
    }
    
    SSHSession accept(SSHSession session, socket_t fd) {        
        auto rc = ssh_bind_accept_fd(this._bind, session._session, fd);
        checkForRCError(rc, this._bind);
        return session;
    }

    void listen() {
        auto rc = ssh_bind_listen(this._bind);
        checkForRCError(rc, this._bind);
    }

    void fdToAccept() {
        ssh_bind_fd_toaccept(this._bind);
    }

    void setOption(T)(BindOption type, T value) {
        auto rc = ssh_bind_options_set(this._bind, cast(ssh_bind_options_e) type, &value);
        checkForRCError(rc, this._bind);
    }
    
    void setOption(BindOption type, string value) {
        auto rc = ssh_bind_options_set(this._bind, cast(ssh_bind_options_e) type, toStrZ(value));
        checkForRCError(rc, this._bind);
    }
    
    void setOption(BindOption type, bool value) {
        int intValue = value ? 1 : 0;
        auto rc = ssh_bind_options_set(this._bind, cast(ssh_bind_options_e) type, &intValue);
        checkForRCError(rc, this._bind);
    }
    
    void setOption(BindOption type, string[] value) {
        auto rc = ssh_bind_options_set(this._bind, cast(ssh_bind_options_e) type, 
            toStrZ(join(value, ",")));
        checkForRCError(rc, this._bind);
    }

    this() {
        auto result = ssh_bind_new();
        if (result is null) {
            throw new SSHException("Error while creating new bind object");
        }
        this._bind = result;

        ssh_callbacks_init(this._callbacks);
    }

    ~this() {
        this._dispose(true);
    }

    override void dispose() {
        this._dispose(false);
    }

    private {
        void _dispose(bool fromDtor) {
            if (this._bind !is null) {
                ssh_bind_free(this._bind);
                this._bind = null;
            }
        }

        ssh_bind _bind;
        ssh_bind_callbacks_struct _callbacks;

        OnIncomingConnectionCallback _onIncomingConnectionCallback;
    }
}



private {
    extern (C) void nativeOnIncomingConnection(ssh_bind, void* userdata) {
        auto bind = cast(SSHBind) userdata;

        if (bind is null || bind._onIncomingConnectionCallback is null) {
            return;
        }

        if (bind !is null) {
            bind._onIncomingConnectionCallback();
        }
    }
}
