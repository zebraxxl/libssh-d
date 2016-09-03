module libssh.session;

import std.string;
import std.algorithm.mutation;

import libssh.c_bindings.libssh;
import libssh.c_bindings.callbacks;
import libssh.c_bindings.sftp;
import libssh.c_bindings.server;
import libssh.errors;
import libssh.utils;
import libssh.channel;
import libssh.message;
import libssh.logging;
import libssh.scp;
import libssh.key;
import libssh.sftp;
import libssh.message;

enum PollFlags : int {
    ReadPending = SSH_READ_PENDING,
    WritePending = SSH_WRITE_PENDING,
}

enum SessionStatusFlags : int {
    Closed = SSH_CLOSED,
    ReadPending = SSH_READ_PENDING,
    ClosedError = SSH_CLOSED_ERROR,
    WritePending = SSH_WRITE_PENDING,
}

enum ServerKnownState : int {
    Ok = ssh_server_known_e.SSH_SERVER_KNOWN_OK,
    Changed = ssh_server_known_e.SSH_SERVER_KNOWN_CHANGED,
    FoundOther = ssh_server_known_e.SSH_SERVER_FOUND_OTHER,
    NotKnown = ssh_server_known_e.SSH_SERVER_NOT_KNOWN,
    FileNotFound = ssh_server_known_e.SSH_SERVER_FILE_NOT_FOUND,
}

enum SessionOption : int {
    Host = ssh_options_e.SSH_OPTIONS_HOST,
    Port = ssh_options_e.SSH_OPTIONS_PORT,
    PortStr = ssh_options_e.SSH_OPTIONS_PORT_STR,
    Fd = ssh_options_e.SSH_OPTIONS_FD,
    User = ssh_options_e.SSH_OPTIONS_USER,
    SshDir = ssh_options_e.SSH_OPTIONS_SSH_DIR,
    Identity = ssh_options_e.SSH_OPTIONS_IDENTITY,
    AddIdentity = ssh_options_e.SSH_OPTIONS_ADD_IDENTITY,
    KnownHosts = ssh_options_e.SSH_OPTIONS_KNOWNHOSTS,
    Timeout = ssh_options_e.SSH_OPTIONS_TIMEOUT,
    TimeoutUsec = ssh_options_e.SSH_OPTIONS_TIMEOUT_USEC,
    Ssh1 = ssh_options_e.SSH_OPTIONS_SSH1,
    Ssh2 = ssh_options_e.SSH_OPTIONS_SSH2,
    LogVerbosity = ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY,
    LogVerbosityStr = ssh_options_e.SSH_OPTIONS_LOG_VERBOSITY_STR,
    CiphersCS = ssh_options_e.SSH_OPTIONS_CIPHERS_C_S,
    CiphersSC = ssh_options_e.SSH_OPTIONS_CIPHERS_S_C,
    CompressionCS = ssh_options_e.SSH_OPTIONS_COMPRESSION_C_S,
    CompressionSC = ssh_options_e.SSH_OPTIONS_COMPRESSION_S_C,
    ProxyCommand = ssh_options_e.SSH_OPTIONS_PROXYCOMMAND,
    BindAddr = ssh_options_e.SSH_OPTIONS_BINDADDR,
    StrictHostkeyCheck = ssh_options_e.SSH_OPTIONS_STRICTHOSTKEYCHECK,
    Compression = ssh_options_e.SSH_OPTIONS_COMPRESSION,
    CompressionLevel = ssh_options_e.SSH_OPTIONS_COMPRESSION_LEVEL,
    KeyExchange = ssh_options_e.SSH_OPTIONS_KEY_EXCHANGE,
    Hostkeys = ssh_options_e.SSH_OPTIONS_HOSTKEYS,
    GssapiServerIdentity = ssh_options_e.SSH_OPTIONS_GSSAPI_SERVER_IDENTITY,
    GssapiClientIdentity = ssh_options_e.SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY,
    GssapiDelegateCredentials = ssh_options_e.SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS,
    HmacCS = ssh_options_e.SSH_OPTIONS_HMAC_C_S,
    HmacSC = ssh_options_e.SSH_OPTIONS_HMAC_S_C,
}

enum SSHProtocolVersion {
    SSH1 = 1,
    SSH2 = 2
}

enum AuthState : int {
    Success = ssh_auth_e.SSH_AUTH_SUCCESS,
    Denied = ssh_auth_e.SSH_AUTH_DENIED,
    Partial = ssh_auth_e.SSH_AUTH_PARTIAL,
    Info = ssh_auth_e.SSH_AUTH_INFO,
    Again = ssh_auth_e.SSH_AUTH_AGAIN,
}

enum AuthMethod : int {
    Unknown = SSH_AUTH_METHOD_UNKNOWN,
    None = SSH_AUTH_METHOD_NONE,
    Password = SSH_AUTH_METHOD_PASSWORD,
    PublicKey = SSH_AUTH_METHOD_PUBLICKEY,
    Hostbased = SSH_AUTH_METHOD_HOSTBASED,
    Interactive = SSH_AUTH_METHOD_INTERACTIVE,
    GSSAPIMic = SSH_AUTH_METHOD_GSSAPI_MIC,
}

alias LogVerbosity = LogLevel;
alias GSSAPICreds = size_t;

class SSHSession : Disposable {
    alias AuthCallback = string delegate(string prompt, bool echo, bool verify);
    alias MessageCallback = bool delegate(SSHSession session, SSHMessage message);
    alias OpenRequestX11Callback = SSHChannel delegate(SSHSession session, string originatorAddres,
        ushort originatorPort);
    alias OnConnectStatusChangedCallback = void delegate(SSHSession session, float v);
    alias OnLogCallback = void delegate(SSHSession session, LogLevel level, string msg);
    alias OnGlobalRequestCallback = void delegate(SSHSession session, SSHMessage message);

    alias ServerAuthGSSAPIMicCallback = AuthState delegate(SSHSession session, string user, 
        string principal);
    alias ServerAuthNoneCallback = AuthState delegate(SSHSession session, string user);
    alias ServerAuthPasswordCallback = AuthState delegate(SSHSession session, string user, 
        string password);
    alias ServerAuthPublicKeyCallback = AuthState delegate(SSHSession session, string user, 
        SSHKey publicKey, PublicKeyState signatureState);
    alias ServerChannelOpenRequestCallback = SSHChannel delegate(SSHSession session);
    alias ServerServiceRequestCallback = bool delegate(SSHSession session, string service);
    alias ServerGSSAPIAcceptSecCtxCallback = bool delegate(SSHSession session, string inputToken,
        out string outputToken);
    alias ServerGSSAPISelectOidCallback = string delegate(SSHSession session, string user,
        string[] oids);

    @property OnConnectStatusChangedCallback onConnectStatusChangedCallback() {
        return this._onConnectStatusChangedCallback;
    }

    @property void onConnectStatusChangedCallback(OnConnectStatusChangedCallback cb) {
        this._onConnectStatusChangedCallback = cb;
        if (cb is null) {
            this._sessionCallbacks.connect_status_function = null;
        } else {
            this._sessionCallbacks.connect_status_function = &nativeConnectStatusCallback;
        }
        ssh_set_callbacks(this._session, &this._sessionCallbacks);
    }

    @property OnLogCallback onLogCallback() {
        return this._onLogCallback;
    }
    
    @property void onLogCallback(OnLogCallback cb) {
        this._onLogCallback = cb;
        if (cb is null) {
            this._sessionCallbacks.log_function = null;
        } else {
            this._sessionCallbacks.log_function = &nativeLogFunction;
        }
        ssh_set_callbacks(this._session, &this._sessionCallbacks);
    }

    @property OnGlobalRequestCallback onGlobalRequestCallback() {
        return this._onGlobalRequestCallback;
    }

    @property void onGlobalRequestCallback(OnGlobalRequestCallback cb) {
        this._onGlobalRequestCallback = cb;
        if (cb is null) {
            this._sessionCallbacks.global_request_function = null;
        } else {
            this._sessionCallbacks.global_request_function = &nativeOnGlobalRequest;
        }
        ssh_set_callbacks(this._session, &this._sessionCallbacks);
    }

    @property AuthCallback authCallback() {
        return this._authCallback;
    }

    @property void authCallback(AuthCallback cb) {
        this._authCallback = cb;
        if (cb is null) {
            this._sessionCallbacks.auth_function = null;
        } else {
            this._sessionCallbacks.auth_function = &nativeAuthCallback;
        }
        ssh_set_callbacks(this._session, &this._sessionCallbacks);
    }

    @property MessageCallback messageCallback() {
        return this._messageCallback;
    }

    @property void messageCallback(MessageCallback cb) {
        this._messageCallback = cb;
        if (cb is null) {
            ssh_set_message_callback(this._session, null, null);
        } else {
            ssh_set_message_callback(this._session, &nativeOnMessageCallback, cast(void*) this);
        }
    }

    @property OpenRequestX11Callback openRequestX11Callback() {
        return this._openRequestX11Callback;
    }

    @property void openRequestX11Callback(OpenRequestX11Callback cb) {
        this._openRequestX11Callback = cb;
        if (cb is null) {
            this._sessionCallbacks.channel_open_request_x11_function = null;
        } else {
            this._sessionCallbacks.channel_open_request_x11_function = &nativeOpenRequestX11Callback;
        }
        ssh_set_callbacks(this._session, &this._sessionCallbacks);
    }


    @property ServerAuthGSSAPIMicCallback serverAuthGSSAPIMicCallback() {
        return this._serverAuthGSSAPIMicCallback;
    }

    @property void serverAuthGSSAPIMicCallback(ServerAuthGSSAPIMicCallback cb) {
        this._serverAuthGSSAPIMicCallback = cb;
        if (cb is null) {
            this._serverCallbacks.auth_gssapi_mic_function = null;
        } else {
            this._serverCallbacks.auth_gssapi_mic_function = &nativeServerAuthGSSAPIMicCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerAuthNoneCallback serverAuthNoneCallback() {
        return this._serverAuthNoneCallback;
    }
    
    @property void serverAuthNoneCallback(ServerAuthNoneCallback cb) {
        this._serverAuthNoneCallback = cb;
        if (cb is null) {
            this._serverCallbacks.auth_none_function = null;
        } else {
            this._serverCallbacks.auth_none_function = &nativeServerAuthNoneCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerAuthPasswordCallback serverAuthPasswordCallback() {
        return this._serverAuthPasswordCallback;
    }
    
    @property void serverAuthPasswordCallback(ServerAuthPasswordCallback cb) {
        this._serverAuthPasswordCallback = cb;
        if (cb is null) {
            this._serverCallbacks.auth_password_function = null;
        } else {
            this._serverCallbacks.auth_password_function = &nativeServerAuthPasswordCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerAuthPublicKeyCallback serverAuthPublicKeyCallback() {
        return this._serverAuthPublicKeyCallback;
    }
    
    @property void serverAuthPublicKeyCallback(ServerAuthPublicKeyCallback cb) {
        this._serverAuthPublicKeyCallback = cb;
        if (cb is null) {
            this._serverCallbacks.auth_pubkey_function = null;
        } else {
            this._serverCallbacks.auth_pubkey_function = &nativeServerAuthPublicKeyCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerChannelOpenRequestCallback serverChannelOpenRequestCallback() {
        return this._serverChannelOpenRequestCallback;
    }

    @property void serverChannelOpenRequestCallback(ServerChannelOpenRequestCallback cb) {
        this._serverChannelOpenRequestCallback = cb;
        if (cb is null) {
            this._serverCallbacks.channel_open_request_session_function = null;
        } else {
            this._serverCallbacks.channel_open_request_session_function = 
                &nativeServerChannelOpenRequestCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerServiceRequestCallback serverServiceRequestCallback() {
        return this._serverServiceRequestCallback;
    }

    @property void serverServiceRequestCallback(ServerServiceRequestCallback cb) {
        this._serverServiceRequestCallback = cb;
        if (cb is null) {
            this._serverCallbacks.service_request_function = null;
        } else {
            this._serverCallbacks.service_request_function = &nativeServerServiceRequestCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerGSSAPIAcceptSecCtxCallback serverGSSAPIAcceptSecCtxCallback() {
        return this._serverGSSAPIAcceptSecCtxCallback;
    }

    @property void serverGSSAPIAcceptSecCtxCallback(ServerGSSAPIAcceptSecCtxCallback cb) {
        this._serverGSSAPIAcceptSecCtxCallback = cb;
        if (cb is null) {
            this._serverCallbacks.gssapi_accept_sec_ctx_function = null;
        } else {
            this._serverCallbacks.gssapi_accept_sec_ctx_function = 
                &nativeServerGSSAPIAcceptSecCtxCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }

    @property ServerGSSAPISelectOidCallback serverGSSAPISelectOidCallback() {
        return this._serverGSSAPISelectOidCallback;
    }

    @property void serverGSSAPIVerifyMicCallback(ServerGSSAPISelectOidCallback cb) {
        this._serverGSSAPISelectOidCallback = cb;
        if (cb is null) {
            this._serverCallbacks.gssapi_select_oid_function = null;
        } else {
            this._serverCallbacks.gssapi_select_oid_function = &nativeServerGSSAPISelectOidCallback;
        }
        ssh_set_server_callbacks(this._session, &this._serverCallbacks);
    }


    @property string cipherIn() {
        return fromStrZ(ssh_get_cipher_in(this._session));
    }

    @property string cipherOut() {
        return fromStrZ(ssh_get_cipher_out(this._session));
    }

    @property string hmacIn() {
        return fromStrZ(ssh_get_hmac_in(this._session));
    }

    @property string hmacOut() {
        return fromStrZ(ssh_get_hmac_out(this._session));
    }
    
    @property string kexAlgo() {
        return fromStrZ(ssh_get_kex_algo(this._session));
    }

    @property string clientBanner() {
        return fromStrZ(ssh_get_clientbanner(this._session));
    }

    @property string serverBanner() {
        return fromStrZ(ssh_get_serverbanner(this._session));
    }

    @property string disconnectMessage() {
        return fromStrZ(ssh_get_disconnect_message(this._session));
    }

    @property socket_t fd() {
        return ssh_get_fd(this._session);
    }

    @property string issueBanner() {
        auto result = ssh_get_issue_banner(this._session);
        scope(exit) ssh_string_free_char(result);
        return copyFromStrZ(result);
    }

    @property int openSSHVersion() {
        return ssh_get_openssh_version(this._session);
    }

    @property PollFlags pollFlags() {
        return cast(PollFlags) ssh_get_poll_flags(this._session);
    }

    @property SSHKey publicKey() {
        ssh_key key;
        auto rc = ssh_get_publickey(this._session, &key);
        checkForRCError(rc, this._session);
        return new SSHKey(key);
    }

    @property SessionStatusFlags status() {
        return cast(SessionStatusFlags) ssh_get_status(this._session);
    }

    @property SSHProtocolVersion sshProtocolVersion() {
        auto result = ssh_get_version(this._session);
        if (result < 0) {
            throw new SSHException(this._session);
        }
        return cast(SSHProtocolVersion) result;
    }

    @property bool isBlocking() {
        return ssh_is_blocking(this._session) == 0 ? false : true;
    }

    @property void isBlocking(bool v) {
        ssh_set_blocking(this._session, v ? 1 : 0);
    }

    @property bool isConnected() {
        return ssh_is_connected(this._session) == 0 ? false : true;
    }

    @property ServerKnownState serverKnownState() {
        auto result = ssh_is_server_known(this._session);
        if (result == ssh_server_known_e.SSH_SERVER_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(ServerKnownState) result;
    }

    @property string lastError() {
        return copyFromStrZ(ssh_get_error(this._session));
    }

    @property void authMethods(AuthMethod am) {
        ssh_set_auth_methods(this._session, cast(int) am);
    }


    @property string host() {
        return this.getOption(SessionOption.Host);
    }

    @property void host(string s) {
        this.setOption(SessionOption.Host, s);
    }

    @property ushort port() {
        uint value;
        auto rc = ssh_options_get_port(this._session, &value);
        checkForRCError(rc, this._session);
        return cast(ushort) value;
    }

    @property void port(ushort port) {
        this.setOption(SessionOption.Port, cast(uint) port);
    }

    @property void port(string port) {
        this.setOption(SessionOption.PortStr, port);
    }

    @property string user() {
        return this.getOption(SessionOption.User);
    }

    @property void user(string v) {
        this.setOption(SessionOption.User, v);
    }

    @property string identity() {
        return this.getOption(SessionOption.Identity);
    }
    
    @property void identity(string v) {
        this.setOption(SessionOption.Identity, v);
    }

    @property string proxyCommand() {
        return this.getOption(SessionOption.ProxyCommand);
    }
    
    @property void proxyCommand(string v) {
        this.setOption(SessionOption.ProxyCommand, v);
    }

    @property void fd(socket_t v) {
        this.setOption(SessionOption.Fd, v);
    }

    @property void bindAddr(string v) {
        this.setOption(SessionOption.BindAddr, v);
    }

    @property void sshDir(string v) {
        this.setOption(SessionOption.SshDir, v);
    }

    @property void knownHosts(string v) {
        this.setOption(SessionOption.KnownHosts, v);
    }

    @property void timeout(long v) {
        this.setOption(SessionOption.Timeout, v);
    }

    @property void timeoutUSec(long v) {
        this.setOption(SessionOption.TimeoutUsec, v);
    }

    @property void allowSSH1(bool v) {
        this.setOption(SessionOption.Ssh1, v);
    }

    @property void allowSSH2(bool v) {
        this.setOption(SessionOption.Ssh2, v);
    }

    @property void logVerbosity(LogVerbosity v) {
        this.setOption(SessionOption.LogVerbosity, cast(int) v);
    }

    @property void ciphersCS(string[] v) {
        this.setOption(SessionOption.CiphersCS, v);
    }

    @property void ciphersCS(string v) {
        this.setOption(SessionOption.CiphersCS, v);
    }

    @property void ciphersSC(string[] v) {
        this.setOption(SessionOption.CiphersSC, v);
    }
    
    @property void ciphersSC(string v) {
        this.setOption(SessionOption.CiphersSC, v);
    }

    @property void keyExchange(string[] v) {
        this.setOption(SessionOption.KeyExchange, v);
    }
    
    @property void keyExchange(string v) {
        this.setOption(SessionOption.KeyExchange, v);
    }

    @property void hostkeys(string[] v) {
        this.setOption(SessionOption.Hostkeys, v);
    }
    
    @property void hostkeys(string v) {
        this.setOption(SessionOption.Hostkeys, v);
    }

    @property void compressionCS(bool v) {
        this.setOption(SessionOption.CompressionCS, v ? "yes" : "no");
    }

    @property void compressionCS(string[] v) {
        this.setOption(SessionOption.CompressionCS, v);
    }
    
    @property void compressionCS(string v) {
        this.setOption(SessionOption.CompressionCS, v);
    }

    @property void compressionSC(bool v) {
        this.setOption(SessionOption.CompressionSC, v ? "yes" : "no");
    }

    @property void compressionSC(string[] v) {
        this.setOption(SessionOption.CompressionSC, v);
    }
    
    @property void compressionSC(string v) {
        this.setOption(SessionOption.CompressionSC, v);
    }

    @property void compression(bool v) {
        this.setOption(SessionOption.Compression, v ? "yes" : "no");
    }
    
    @property void compression(string[] v) {
        this.setOption(SessionOption.Compression, v);
    }
    
    @property void compression(string v) {
        this.setOption(SessionOption.Compression, v);
    }

    @property void compressonLevel(int v) {
        assert(v >= 1 && v <= 9);
        this.setOption(SessionOption.CompressionLevel, v);
    }

    @property strictHostkeyCheck(bool v) {
        this.setOption(SessionOption.StrictHostkeyCheck, v);
    }

    @property gssapiServerIdentity(string v) {
        this.setOption(SessionOption.GssapiServerIdentity, v);
    }

    @property gssapiClientIdentity(string v) {
        this.setOption(SessionOption.GssapiClientIdentity, v);
    }

    @property gssapiDelegateCredentials(bool v) {
        this.setOption(SessionOption.GssapiDelegateCredentials, v);
    }


    version (LIBSSH_WITH_GSSAPI) {
        @property GSSAPICreds gssapiCreds() {
            return cast(GSSAPICreds) ssh_gssapi_get_creds(this._session);
        }
        
        @property void gssapiCreds(GSSAPICreds v) {
            ssh_gssapi_set_creds(this._session, cast(ssh_gssapi_creds) v);
        }
    }


    this() {
        auto newSession = ssh_new();
        checkForNullError(newSession, "Error while creating session object");
        this(newSession);
    }

    ~this() {
        this._dispose(true);
    }

    override void dispose() {
        this._dispose(false);
    }

    /**
     * Returns false  if the session is in nonblocking mode, and call must be done again.
     **/
    bool connect() {
        auto rc = ssh_connect(this._session);
        if (rc == SSH_AGAIN) {
            return false;
        }
        checkForRCError(rc, this._session);
        return true;
    }

    void disconnect() {
        ssh_disconnect(this._session);
    }

    /**
     * Returns false on timeout
     **/
    bool blockingFlush(int timeout) {
        auto rc = ssh_blocking_flush(this._session, timeout);
        if (rc == SSH_AGAIN) {
            return false;
        }
        checkForRCError(rc, this._session);
        return true;
    }

    SSHSession getCopy() {
        ssh_session newSession;
        auto rc = ssh_options_copy(this._session, &newSession);
        checkForRCError(rc, this._session);
        return new SSHSession(newSession);
    }

    string getOption(SessionOption type) {
        char* value;
        auto rc = ssh_options_get(this._session, cast(ssh_options_e) type, &value);
        checkForRCError(rc, this._session);
        scope(exit) ssh_string_free_char(value);
        return copyFromStrZ(value);
    }

    void setOption(T)(SessionOption type, T value) {
        auto rc = ssh_options_set(this._session, cast(ssh_options_e) type, &value);
        checkForRCError(rc, this._session);
    }

    void setOption(SessionOption type, string value) {
        auto rc = ssh_options_set(this._session, cast(ssh_options_e) type, toStrZ(value));
        checkForRCError(rc, this._session);
    }

    void setOption(SessionOption type, bool value) {
        int intValue = value ? 1 : 0;
        auto rc = ssh_options_set(this._session, cast(ssh_options_e) type, &intValue);
        checkForRCError(rc, this._session);
    }

    void setOption(SessionOption type, string[] value) {
        auto rc = ssh_options_set(this._session, cast(ssh_options_e) type, toStrZ(join(value, ",")));
        checkForRCError(rc, this._session);
    }

    void parseConfig(string fileName) {
        auto rc = ssh_options_parse_config(this._session, toStrZ(fileName));
        checkForRCError(rc, this._session);
    }

    void sendDebug(string message, bool alwaysDisplay) {
        auto rc = ssh_send_debug(this._session, toStrZ(message), alwaysDisplay ? 1 : 0);
        checkForRCError(rc, this._session);
    }

    void sendIgnore(string message) {
        auto rc = ssh_send_ignore(this._session, toStrZ(message));
        checkForRCError(rc, this._session);
    }

    void setFdExcept() {
        ssh_set_fd_except(this._session);
    }

    void setFdToRead() {
        ssh_set_fd_toread(this._session);
    }

    void setFdToWrite() {
        ssh_set_fd_towrite(this._session);
    }

    void silentDisconnect() {
        ssh_silent_disconnect(this._session);
    }

    void writeKnownHost() {
        auto rc = ssh_write_knownhost(this._session);
        checkForRCError(rc, this._session);
    }

    SSHChannel newChannel() {
        auto result = ssh_channel_new(this._session);
        checkForNullError(result, this._session);

        return new SSHChannel(this, result);
    }

    SSHMessage getMessage() {
        auto result = ssh_message_get(this._session);
        if (result is null) {
            return null;
        }
        return new SSHMessage(this, result);
    }


    AuthMethod userauthList(string username) {
        return cast(AuthMethod) ssh_userauth_list(this._session, toStrZ(username));
    }

    AuthState userauthNone(string username) {
        auto rc = ssh_userauth_none(this._session, toStrZ(username));
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    AuthState userauthPassword(string username, string password) {
        auto rc = ssh_userauth_password(this._session, toStrZ(username), toStrZ(password));
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    AuthState userauthPublicKey(string username, const SSHKey privateKey) {
        assert(privateKey !is null);

        auto rc = ssh_userauth_publickey(this._session, toStrZ(username), privateKey._key);
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    AuthState userauthTryPublicKey(string username, const SSHKey publicKey) {
        assert(publicKey !is null);
        
        auto rc = ssh_userauth_publickey(this._session, toStrZ(username), publicKey._key);
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    AuthState userauthPublicKeyAuto(string username, string passPhrase) {
        auto rc = ssh_userauth_publickey_auto(this._session, toStrZ(username), toStrZ(passPhrase));
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    version(Windows) { } else {
        AuthState userauthAgent(string username) {
            auto rc = ssh_userauth_agent(this._session, toStrZ(username));
            if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
                throw new SSHException(this._session);
            }
            return cast(AuthState) rc;
        }
    }

    AuthState userauthGSSAPI() {
        auto rc = ssh_userauth_gssapi(this._session);
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    AuthState userauthKeyboardInteractive(string username) {
        auto rc = ssh_userauth_kbdint(this._session, toStrZ(username), null);
        if (rc == ssh_auth_e.SSH_AUTH_ERROR) {
            throw new SSHException(this._session);
        }
        return cast(AuthState) rc;
    }

    int userauthKeyboardInteractiveGetNAnswers() {
        auto result = ssh_userauth_kbdint_getnanswers(this._session);
        if (result == SSH_ERROR) {
            throw new SSHException(this._session);
        }
        return result;
    }

    string userauthKeyboardInteractiveGetAnswer(uint i) {
        auto result = ssh_userauth_kbdint_getanswer(this._session, i);
        if (result is null) {
            throw new SSHException(this._session);
        }
        return fromStrZ(result);
    }

    int userauthKeyboardInteractiveGetNPrompts() {
        auto result = ssh_userauth_kbdint_getnprompts(this._session);
        if (result == SSH_ERROR) {
            throw new SSHException(this._session);
        }
        return result;
    }

    string userauthKeyboardInteractiveGetPrompt(uint i, out bool echo) {
        char echoChar;
        auto result = ssh_userauth_kbdint_getprompt(this._session, i, &echoChar);
        if (result is null) {
            throw new SSHException(this._session);
        }
        echo = echoChar == 0 ? false : true;
        return fromStrZ(result);
    }

    string userauthKeyboardInteractiveGetPrompt(uint i) {
        auto result = ssh_userauth_kbdint_getprompt(this._session, i, null);
        if (result is null) {
            throw new SSHException(this._session);
        }
        return fromStrZ(result);
    }

    string userauthKeyboardInteractiveGetInstruction() {
        auto result = ssh_userauth_kbdint_getinstruction(this._session);
        if (result is null) {
            throw new SSHException(this._session);
        }
        return fromStrZ(result);
    }

    string userauthKeyboardInteractiveGetName() {
        auto result = ssh_userauth_kbdint_getname(this._session);
        if (result is null) {
            throw new SSHException(this._session);
        }
        return fromStrZ(result);
    }

    void userauthKeyboardInteractiveSetAnswer(uint i, string answer) {
        auto result = ssh_userauth_kbdint_setanswer(this._session, i, toStrZ(answer));
        checkForRCError(result, this._session);
    }


    SSHChannel acceptForward(int timeoutMs, out ushort destPort) {
        int destPortInt;
        auto result = ssh_channel_accept_forward(this._session, timeoutMs, &destPortInt);
        if (result is null) {
            return null;
        }
        destPort = cast(ushort) destPortInt;
        return new SSHChannel(this, result);
    }

    SSHChannel acceptForward(int timeoutMs) {
        auto result = ssh_channel_accept_forward(this._session, timeoutMs, null);
        if (result is null) {
            return null;
        }
        return new SSHChannel(this, result);
    }

    /**
     * return false if in nonblocking mode and call has to be done again.
     * */
    bool listenForward(string address, ushort port, out ushort boundPort) {
        int boundPortInt;
        auto rc = ssh_channel_listen_forward(this._session, toStrZ(address), port, &boundPortInt);
        if (rc == SSH_AGAIN) {
            return false;
        }
        checkForRCError(rc, this._session);
        boundPort = cast(ushort) boundPortInt;
        return true;
    }

    void cancelForward(string address, ushort port) {
        auto rc = ssh_channel_cancel_forward(this._session, toStrZ(address), port);
        checkForRCError(rc, this._session);
    }


    SSHSCP newScp(SCPMode mode, string location) {
        auto result = ssh_scp_new(this._session, mode, toStrZ(location));
        checkForNullError(result, this._session);
        return new SSHSCP(this, result);
    }

    SFTPSession newSFTP() {
        auto result = sftp_new(this._session);
        checkForNullError(result, this._session);
        return new SFTPSession(this, result);
    }

    SFTPSession newSFTP(SSHChannel channel) {
        auto result = sftp_new_channel(this._session, channel._channel);
        checkForNullError(result, this._session);
        return new SFTPSession(this, result);
    }

    version (LIBSSH_WITH_SERVER) {
        SFTPSession newSFTPServer(SSHChannel channel) {
            auto result = sftp_server_new(this._session, channel._channel);
            mixin CheckForNullError!(result, this._session);
            return new SFTPSession(this, result);
        }
    }


    void handleKeyExchange() {
        auto rc = ssh_handle_key_exchange(this._session);
        checkForRCError(rc, this._session);
    }

    package {        
        this(ssh_session session) {
            this._session = session;
            
            ssh_callbacks_init(this._sessionCallbacks);
            this._sessionCallbacks.userdata = cast(void*) this;
//
            ssh_callbacks_init(this._serverCallbacks);
            this._serverCallbacks.userdata = cast(void*) this;
            
            this._authCallback = null;
        }

        ssh_session _session;

        void registerChannel(SSHChannel ch) {
            this._channels ~= ch;
        }

        void freeChannel(SSHChannel toDel) {
            this._channels = remove!(a => a == toDel)(this._channels);
        }
    }

    private {
        ssh_callbacks_struct _sessionCallbacks;
        ssh_server_callbacks_struct _serverCallbacks;

        SSHChannel[] _channels = [];

        OnConnectStatusChangedCallback _onConnectStatusChangedCallback;
        OnLogCallback _onLogCallback;
        OnGlobalRequestCallback _onGlobalRequestCallback;
        AuthCallback _authCallback;
        MessageCallback _messageCallback;
        OpenRequestX11Callback _openRequestX11Callback;

        ServerAuthGSSAPIMicCallback _serverAuthGSSAPIMicCallback;
        ServerAuthNoneCallback _serverAuthNoneCallback;
        ServerAuthPasswordCallback _serverAuthPasswordCallback;
        ServerAuthPublicKeyCallback _serverAuthPublicKeyCallback;
        ServerChannelOpenRequestCallback _serverChannelOpenRequestCallback;
        ServerServiceRequestCallback _serverServiceRequestCallback;
        ServerGSSAPIAcceptSecCtxCallback _serverGSSAPIAcceptSecCtxCallback;
        ServerGSSAPISelectOidCallback _serverGSSAPISelectOidCallback;

        void _dispose(bool fromDtor) {
            if (this._session !is null) {
                foreach (channel; this._channels) {
                    channel.dispose();
                }
                this._channels = null;

                ssh_free(this._session);
                this._session = null;
            }
        }
    }
}

bool sshFinalize() {
    auto rc = ssh_finalize();
    return rc == SSH_OK ? true : false;
}

private {
    extern(C) void nativeConnectStatusCallback(void* userdata, float status) {
        auto session = cast(SSHSession) userdata;

        if (session is null || session._onConnectStatusChangedCallback) {
            return;
        }

        session._onConnectStatusChangedCallback(session, status);
    }

    extern(C) void nativeLogFunction(ssh_session session, int priority, const char* message, 
            void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;

        if (sessionObj is null || sessionObj._onLogCallback is null) {
            return;
        }

        sessionObj._onLogCallback(sessionObj, cast(LogLevel) priority, fromStrZ(message));
    }

    extern(C) int nativeAuthCallback(const char *prompt, char *buf, size_t len,
            int echo, int verify, void *userdata) {
        auto session = cast(SSHSession) userdata;

        if (session is null || session._authCallback is null) {
            return SSH_ERROR;
        }

        try {
            auto result = session._authCallback(fromStrZ(prompt), echo == 0 ? false : true, 
                verify == 0 ? false : true);
            if (result is null) {
                return SSH_ERROR;
            }

            if (len < result.length + 1) {
                return SSH_ERROR;
            }

            import core.stdc.string : memcpy;
            memcpy(buf, result.ptr, result.length);
            buf[result.length] = 0;

            return SSH_OK;
        } catch (Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) void nativeOnGlobalRequest(ssh_session, ssh_message message, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;

        if (sessionObj is null || sessionObj._onGlobalRequestCallback is null) {
            return;
        }

        auto messageObj = new SSHMessage(sessionObj, message);
        scope(exit) messageObj.dispose();
        sessionObj._onGlobalRequestCallback(sessionObj, messageObj);
    }

    extern(C) int nativeOnMessageCallback(ssh_session session, ssh_message message, 
            void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;

        if (sessionObj is null || sessionObj._messageCallback is null) {
            return SSH_ERROR;
        }

        auto messageObj = new SSHMessage(sessionObj, message);
        scope(exit) messageObj.dispose();

        try {
            auto result = sessionObj._messageCallback(sessionObj, messageObj);
            if (!result)
                return SSH_ERROR;
            return SSH_OK;
        } catch (Exception) {
            return SSH_ERROR;
        }
            
    }

    extern(C) ssh_channel nativeOpenRequestX11Callback(ssh_session session, 
            const char* originator_address, int originator_port, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;

        if (sessionObj is null || sessionObj._openRequestX11Callback is null) {
            return null;
        }

        try {
            auto result = sessionObj._openRequestX11Callback(sessionObj, 
                fromStrZ(originator_address), cast(ushort) originator_port);
            if (result is null) {
                return null;
            }
            return result._channel;
        } catch (Exception) {
            return null;
        }
    }

    extern(C) int nativeServerAuthGSSAPIMicCallback(ssh_session, const char* user,
            const char* principal, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;
        
        if (sessionObj is null || sessionObj._serverAuthGSSAPIMicCallback is null) {
            return SSH_ERROR;
        }

        try {
            return cast(int) sessionObj._serverAuthGSSAPIMicCallback(sessionObj, 
                fromStrZ(user), fromStrZ(principal));
        } catch (Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) int nativeServerAuthNoneCallback(ssh_session, const char* user,
            void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;
        
        if (sessionObj is null || sessionObj._serverAuthNoneCallback is null) {
            return SSH_ERROR;
        }
        
        try {
            return cast(int) sessionObj._serverAuthNoneCallback(sessionObj, 
                fromStrZ(user));
        } catch (Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) int nativeServerAuthPasswordCallback(ssh_session, const char* user,
            const char* password, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;
        
        if (sessionObj is null || sessionObj._serverAuthPasswordCallback is null) {
            return SSH_ERROR;
        }
        
        try {
            return cast(int) sessionObj._serverAuthPasswordCallback(sessionObj, 
                fromStrZ(user), fromStrZ(password));
        } catch (Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) int nativeServerAuthPublicKeyCallback(ssh_session, const char* user,
            ssh_key_struct* key, byte signatureState, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;
        
        if (sessionObj is null || sessionObj._serverAuthPublicKeyCallback is null) {
            return SSH_ERROR;
        }
        
        try {
            return cast(int) sessionObj._serverAuthPublicKeyCallback(sessionObj, 
                fromStrZ(user), new SSHKey(key), cast(PublicKeyState) signatureState);
        } catch (Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) ssh_channel nativeServerChannelOpenRequestCallback(ssh_session, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;

        if (sessionObj is null || sessionObj._serverChannelOpenRequestCallback is null) {
            return null;
        }

        try {
            auto result = sessionObj._serverChannelOpenRequestCallback(sessionObj);
            if (result is null) {
                return null;
            }
            return result._channel;
        } catch(Exception) {
            return null;
        }
    }

    extern(C) int nativeServerServiceRequestCallback(ssh_session, const char* service, 
            void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;

        if (sessionObj is null || sessionObj._serverServiceRequestCallback is null) {
            return SSH_ERROR;
        }

        try {
            if (sessionObj._serverServiceRequestCallback(sessionObj, fromStrZ(service))) {
                return SSH_OK;
            } else {
                return SSH_ERROR;
            }
        } catch(Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) int nativeServerGSSAPIAcceptSecCtxCallback(ssh_session session, 
            ssh_string input_token, ssh_string *output_token, void *userdata) {
        auto sessionObj = cast(SSHSession) userdata;
        
        if (sessionObj is null || sessionObj._serverGSSAPIAcceptSecCtxCallback is null) {
            return SSH_ERROR;
        }
        
        try {
            auto inputTokenData = ssh_string_data(input_token);
            auto inputTokenLen = ssh_string_len(input_token);
            string inputTokenStr = (cast(immutable(char)*) inputTokenData)[0 .. inputTokenLen];
            string outputTokenStr;

            auto result = sessionObj._serverGSSAPIAcceptSecCtxCallback(sessionObj, inputTokenStr,
                outputTokenStr);
            if (outputTokenStr is null) {
                *output_token = null;
            } else {
                *output_token = ssh_string_new(outputTokenStr.length);
                ssh_string_fill(*output_token, outputTokenStr.ptr, outputTokenStr.length);
            }

            if (result) {
                return SSH_OK;
            } else {
                return SSH_ERROR;
            }
        } catch(Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) ssh_string nativeServerGSSAPISelectOidCallback(ssh_session session, const char* user,
            int n_oid, ssh_string* oids, void* userdata) {
        auto sessionObj = cast(SSHSession) userdata;
        
        if (sessionObj is null || sessionObj._serverGSSAPISelectOidCallback is null) {
            string[] oidsArr = new string[n_oid];
            for (auto i = 0; i < n_oid; i++) {
                auto oidData = ssh_string_data(oids[i]);
                auto oidLen = ssh_string_len(oids[i]);
                oidsArr[i] = (cast(immutable(char)*) oidData)[0 .. oidLen];
            }
            auto result = sessionObj._serverGSSAPISelectOidCallback(sessionObj,
                fromStrZ(user), oidsArr);
            if (result is null) {
                return null;
            }

            for (auto i = 0; i < n_oid; i++) {
                if (oidsArr[i] == result) {
                    return oids[i];
                }
            }

            return null;
        }
        
        try {
            return null;
        } catch(Exception) {
            return null;
        }
    }
}
