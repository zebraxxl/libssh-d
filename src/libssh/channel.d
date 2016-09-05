module libssh.channel;

import core.time;
import std.algorithm.searching;
import std.algorithm.mutation;

import libssh.c_bindings.libssh;
import libssh.c_bindings.server;
import libssh.c_bindings.callbacks;
import libssh.c_bindings.ctypes;
import libssh.errors;
import libssh.utils;
import libssh.session;

class SSHChannelSet {
    this() {
    }

    void add(SSHChannel channel) {
        if (!this._channels.canFind(channel)) {
            this._channels ~= channel;
        }
    }

    void remove(SSHChannel channel) {
        this._channels = std.algorithm.mutation.remove!(a => a == channel)(this._channels);
    }

    bool isSet(SSHChannel channel) {
        return this._settedChannels.canFind(channel._channel);
    }

    void reset() {
        this._settedChannels = [];
    }

    private {
        SSHChannel[] _channels = [];
        ssh_channel[] _settedChannels = [];
    }
}

class SSHChannel : Disposable {
    enum PollEof = int.min;
    enum ReadAgain = int.min;
    enum WriteAgain = int.min;

    alias OnDataCallback = uint delegate(SSHChannel channel, void[] data, bool isStdErr);
    alias OnPtyRequestCallback = bool delegate(SSHChannel channel, string term, int width,
        int height, int pxWidth, int pxHeight);
    alias OnShellRequestCallback = bool delegate(SSHChannel channel);
    alias OnPtyWindowChangeRequestCallback = bool delegate(SSHChannel channel, int width, 
        int height, int pxWidth, int pxHeight);
    alias OnExecRequestCallback = bool delegate(SSHChannel channel, string command);
    alias OnEnvRequestCallback = bool delegate(SSHChannel channel, string name, string value);
    alias OnSubsystemRequestCallback = bool delegate(SSHChannel channel, string subsystem);
    alias OnEOFCallback = void delegate(SSHChannel channel);
    alias OnCloseCallback = void delegate(SSHChannel channel);
    alias OnSignalCallback = void delegate(SSHChannel channel, string signal);    // TODO: maybe signal should be enum?
    alias OnExitStatusCallback = void delegate(SSHChannel channel, int exitStatus);
    alias OnExitSignalCallback = void delegate(SSHChannel channel, string signal, bool isCoreDump,
        string errMsg, string lang); // TODO: maybe signal should be enum?
    alias OnAuthAgentRequestCallback = void delegate(SSHChannel channel);
    alias OnX11RequestCallback = void delegate(SSHChannel channel, bool isSingleConnection, 
        string authProtocol, string authCookie, uint screenNumber);

    @property onEOFCallback() {
        return this._onEOFCallback;
    }
    
    @property void onEOFCallback(OnEOFCallback cb) {
        this._onEOFCallback = cb;
        if (cb is null) {
            this._callbacks.channel_eof_function = null;
        } else {
            this._callbacks.channel_eof_function = &nativeOnEOFCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }
    
    @property onCloseCallback() {
        return this._onCloseCallback;
    }
    
    @property void onCloseCallback(OnCloseCallback cb) {
        this._onCloseCallback = cb;
        if (cb is null) {
            this._callbacks.channel_close_function = null;
        } else {
            this._callbacks.channel_close_function = &nativeOnCloseCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }
    
    @property onSignalCallback() {
        return this._onSignalCallback;
    }
    
    @property void onSignalCallback(OnSignalCallback cb) {
        this._onSignalCallback = cb;
        if (cb is null) {
            this._callbacks.channel_signal_function = null;
        } else {
            this._callbacks.channel_signal_function = &nativeOnSignalCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }
    
    @property onExitStatusCallback() {
        return this._onExitStatusCallback;
    }
    
    @property void onExitStatusCallback(OnExitStatusCallback cb) {
        this._onExitStatusCallback = cb;
        if (cb is null) {
            this._callbacks.channel_exit_status_function = null;
        } else {
            this._callbacks.channel_exit_status_function = &nativeOnExitStatusCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }
    
    @property onExitSignalCallback() {
        return this._onExitSignalCallback;
    }
    
    @property void onExitSignalCallback(OnExitSignalCallback cb) {
        this._onExitSignalCallback = cb;
        if (cb is null) {
            this._callbacks.channel_exit_signal_function = null;
        } else {
            this._callbacks.channel_exit_signal_function = &nativeOnExitSignalCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }
    
    @property onAuthAgentRequestCallback() {
        return this._onAuthAgentRequestCallback;
    }
    
    @property void onAuthAgentRequestCallback(OnAuthAgentRequestCallback cb) {
        this._onAuthAgentRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_auth_agent_req_function = null;
        } else {
            this._callbacks.channel_auth_agent_req_function = &nativeOnAuthAgentRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }
    
    @property onX11RequestCallback() {
        return this._onX11RequestCallback;
    }
    
    @property void onX11RequestCallback(OnX11RequestCallback cb) {
        this._onX11RequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_x11_req_function = null;
        } else {
            this._callbacks.channel_x11_req_function = &nativeOnX11tRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnDataCallback onDataCallback() {
        return this._onDataCallback;
    }

    @property void onDataCallback(OnDataCallback cb) {
        this._onDataCallback = cb;
        if (cb is null) {
            this._callbacks.channel_data_function = null;
        } else {
            this._callbacks.channel_data_function = &nativeOnData;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnPtyRequestCallback onPtyRequestCallback() {
        return this._onPtyRequestCallback;
    }

    @property void onPtyRequestCallback(OnPtyRequestCallback cb) {
        this._onPtyRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_pty_request_function = null;
        } else {
            this._callbacks.channel_pty_request_function = &nativeOnPtyRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnShellRequestCallback onShellRequestCallback() {
        return this._onShellRequestCallback;
    }
    
    @property void onShellRequestCallback(OnShellRequestCallback cb) {
        this._onShellRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_shell_request_function = null;
        } else {
            this._callbacks.channel_shell_request_function = &nativeOnShellRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnPtyWindowChangeRequestCallback onPtyWindowChangeRequestCallback() {
        return this._onPtyWindowChangeRequestCallback;
    }
    
    @property void onPtyWindowChangeRequestCallback(OnPtyWindowChangeRequestCallback cb) {
        this._onPtyWindowChangeRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_pty_window_change_function = null;
        } else {
            this._callbacks.channel_pty_window_change_function = &nativeOnPtyWindowChangeRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnExecRequestCallback onExecRequestCallback() {
        return this._onExecRequestCallback;
    }

    @property void onExecRequestCallback(OnExecRequestCallback cb) {
        this._onExecRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_exec_request_function = null;
        } else {
            this._callbacks.channel_exec_request_function = &nativeOnExecRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnEnvRequestCallback onEnvRequestCallback() {
        return this._onEnvRequestCallback;
    }

    @property void onEnvRequestCallback(OnEnvRequestCallback cb) {
        this._onEnvRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_env_request_function = null;
        } else {
            this._callbacks.channel_env_request_function = &nativeOnEnvRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property OnSubsystemRequestCallback onSubsystemRequestCallback() {
        return this._onSubsystemRequestCallback;
    }
    
    @property void onSubsystemRequestCallback(OnSubsystemRequestCallback cb) {
        this._onSubsystemRequestCallback = cb;
        if (cb is null) {
            this._callbacks.channel_subsystem_request_function = null;
        } else {
            this._callbacks.channel_subsystem_request_function = &nativeOnSubsystemRequestCallback;
        }
        ssh_set_channel_callbacks(this._channel, &this._callbacks);
    }

    @property SSHSession parent() {
        return this._parent;
    }

    @property int exitStatus() {
        return ssh_channel_get_exit_status(this._channel);
    }

    @property bool isClosed() {
        return ssh_channel_is_closed(this._channel) == 0 ? false : true;
    }

    @property bool isEof() {
        return ssh_channel_is_eof(this._channel) == 0 ? false : true;
    }

    @property bool isOpen() {
        return ssh_channel_is_open(this._channel) == 0 ? false : true;
    }

    @property void blocking(bool v) {
        ssh_channel_set_blocking(this._channel, v ? 1 : 0);
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool openSession() {
        auto rc = ssh_channel_open_session(this._channel);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }
    
    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool requestExec(string cmd) {
        auto rc = ssh_channel_request_exec(this._channel, toStrZ(cmd));
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    } 

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool requestPty() {
        auto rc = ssh_channel_request_pty(this._channel);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool requestPtySize(string terminalType = "vt100", int width = 80, int height = 25) {
        auto rc = ssh_channel_request_pty_size(this._channel, toStrZ(terminalType), width, height);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool requestShell() {
        auto rc = ssh_channel_request_shell(this._channel);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool requestSubsystem(string subsystem) {
        auto rc = ssh_channel_request_subsystem(this._channel, toStrZ(subsystem));
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool requestX11(bool singleConnection, string protocol, string cookie, 
            int screenNumber) {
        auto rc = ssh_channel_request_x11(this._channel, singleConnection ? 1 : 0,
            toStrZ(protocol), toStrZ(cookie), screenNumber);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }
    
    // TODO: maybe signal should be enum?
    void sendSignal(string signal) {
        auto rc = ssh_channel_request_send_signal(this._channel, toStrZ(signal));
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }

    void sendEof() {
        auto rc = ssh_channel_send_eof(this._channel);
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }

    // TODO: maybe signal should be enum?
    void sendExitSignal(string signal, bool core, string errMsg, string lang) {
        auto rc = ssh_channel_request_send_exit_signal(this._channel, toStrZ(signal),
            core ? 1 : 0, toStrZ(errMsg), toStrZ(lang));
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }

    void sendExitStatus(int exitStatus) {
        auto rc = ssh_channel_request_send_exit_status(this._channel, exitStatus);
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }

    /**
     * returns SSHChannel.PollEof if EOF
     **/
    int poll(bool isStdErr) {
        auto rc = ssh_channel_poll(this._channel, isStdErr ? 1 : 0);
        if (rc == SSH_EOF) {
            return SSHChannel.PollEof;
        }
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        return rc;
    }

    /**
     * returns SSHChannel.PollEof if EOF
     **/
    int pollTimeout(int timeout, bool isStdErr) {
        auto rc = ssh_channel_poll_timeout(this._channel, timeout, isStdErr ? 1 : 0);
        if (rc == SSH_EOF) {
            return -1;
        }
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        return rc;
    }

    /**
     * returns SSHChannel.ReadAgain in nonblocking mode
     **/
    int read(void[] dest, bool isStdErr) {
        auto rc = ssh_channel_read(this._channel, dest.ptr, cast(uint) dest.length, 
            isStdErr ? 1 : 0);
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        if (rc == SSH_AGAIN) {
            return SSHChannel.ReadAgain;
        }
        return rc;
    }

    /**
     * returns SSHChannel.ReadAgain in nonblocking mode
     **/
    int readNonBlocking(void[] dest, bool isStdErr) {
        auto rc = ssh_channel_read_nonblocking(this._channel, dest.ptr, cast(uint) dest.length, 
            isStdErr ? 1 : 0);
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        if (rc == SSH_AGAIN) {
            return SSHChannel.ReadAgain;
        }
        return rc;
    }

    /**
     * returns SSHChannel.ReadAgain in nonblocking mode
     **/
    int readTimeout(void[] dest, bool isStdErr, int timeout) {
        auto rc = ssh_channel_read_timeout(this._channel, dest.ptr, cast(uint) dest.length, 
            isStdErr ? 1 : 0, timeout);
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        if (rc == SSH_AGAIN) {
            return SSHChannel.ReadAgain;
        }
        return rc;
    }

    /**
     * returns SSHChannel.WriteAgain in nonblocking mode
     **/
    int write(const void[] src) {
        auto rc = ssh_channel_write(this._channel, src.ptr, cast(uint) src.length);
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        if (rc == SSH_AGAIN) {
            return SSHChannel.WriteAgain;
        }
        return rc;
    }

    /**
     * returns SSHChannel.WriteAgain in nonblocking mode
     **/
    int writeStdErr(const void[] src) {
        auto rc = ssh_channel_write_stderr(this._channel, src.ptr, cast(uint) src.length);
        if (rc == SSH_ERROR) {
            throw new SSHException(this._parent._session);
        }
        if (rc == SSH_AGAIN) {
            return SSHChannel.WriteAgain;
        }
        return rc;
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool setEnv(string name, string value) {
        auto rc = ssh_channel_request_env(this._channel, toStrZ(name), toStrZ(value));
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    void changePtySize(int width, int height) {
        auto rc = ssh_channel_change_pty_size(this._channel, width, height);
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }

    SSHChannel acceptX11(int timeoutMs) {
        auto result = ssh_channel_accept_x11(this._channel, timeoutMs);
        if (result is null) {
            return null;
        }
        return new SSHChannel(this._parent, result);
    }

    /**
     * return false if in nonblocking mode and call has to be done again.
     * */
    bool openAuthAgent() {
        auto rc = ssh_channel_open_auth_agent(this._channel);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * return false if in nonblocking mode and call has to be done again.
     * */
    bool openForward(string remoteHost, ushort remotePort, string srcHost, 
            ushort localPort) {
        assert(remoteHost !is null);
        auto rc = ssh_channel_open_forward(this._channel, toStrZ(remoteHost), remotePort,
            toStrZ(srcHost), localPort);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * return false if in nonblocking mode and call has to be done again.
     * */
    bool openReverseForward(string remoteHost, ushort remotePort, string srcHost,
            ushort localPort) {
        assert(remoteHost !is null);
        auto rc = ssh_channel_open_reverse_forward(this._channel, toStrZ(remoteHost), remotePort,
            toStrZ(srcHost), localPort);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }

    /**
     * returns false if in nonblocking mode and call has to be done again.
     **/
    bool openX11(string origAddr, ushort origPort) {
        auto rc = ssh_channel_open_x11(this._channel, toStrZ(origAddr), origPort);
        if (rc == SSH_AGAIN) {
            return false;
        }
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
        return true;
    }


    void close() {
        auto rc = ssh_channel_close(this._channel);
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }

    override void dispose() {
        this._dispose(false);
    }

    /**
     * return false if the select(2) syscall was interrupted, then relaunch the function.
     * */
    static bool select(SSHChannelSet readChans, SSHChannelSet writeChans, 
            SSHChannelSet exceptChans, Duration timeout) {

        timeval timeoutVal;
        timeout.split!("seconds", "usecs")(timeoutVal.tv_sec, timeoutVal.tv_usec);

        ssh_channel[] forRead = null;
        ssh_channel[] forWrite = null;
        ssh_channel[] forExcept = null;
       
        if (readChans !is null && readChans._channels.length > 0) {
            forRead = new ssh_channel[readChans._channels.length + 1];
            for (auto i = 0; i < readChans._channels.length; i++) {
                forRead[i] = readChans._channels[i]._channel;
            }
            forRead[readChans._channels.length] = null;
        }

        if (writeChans !is null && writeChans._channels.length > 0) {
            forWrite = new ssh_channel[writeChans._channels.length + 1];
            for (auto i = 0; i < writeChans._channels.length; i++) {
                forWrite[i] = writeChans._channels[i]._channel;
            }
            forWrite[writeChans._channels.length] = null;
        }

        if (exceptChans !is null && exceptChans._channels.length > 0) {
            forExcept = new ssh_channel[exceptChans._channels.length + 1];
            for (auto i = 0; i < exceptChans._channels.length; i++) {
                forExcept[i] = exceptChans._channels[i]._channel;
            }
            forExcept[exceptChans._channels.length] = null;
        }

        ssh_channel* forReadPtr = forRead !is null ? forRead.ptr : null;
        ssh_channel* forWritePtr = forWrite !is null ? forWrite.ptr : null;
        ssh_channel* forExceptPtr = forExcept !is null ? forExcept.ptr : null;

        auto rc = ssh_channel_select(forReadPtr, forWritePtr, forExceptPtr, &timeoutVal);

        if (rc == ssh_error_types_e.SSH_EINTR || rc == SSH_AGAIN) {
            return false;
        }
        checkForRCError(rc, rc);

        size_t i = 0;
        if (forRead !is null) {
            while (forRead[i] !is null) {
                readChans._settedChannels ~= forRead[i];
                i += 1;
            }
        }

        if (forWrite !is null) {
            i = 0;
            while (forWrite[i] !is null) {
                writeChans._settedChannels ~= forWrite[i];
                i += 1;
            }
        }

        if (forExcept !is null) {
            i = 0;
            while (forExcept[i] !is null) {
                exceptChans._settedChannels ~= forExcept[i];
                i += 1;
            }
        }

        return true;
    }

    ~this() {
        this._dispose(true);
    }

    package {
        this(SSHSession parent, ssh_channel channel) {
            this._parent = parent;
            this._channel = channel;
            parent.registerChannel(this);

            ssh_callbacks_init(this._callbacks);
            this._callbacks.userdata = cast(void*) this;
        }

        ssh_channel _channel;
    }

    private {
        SSHSession _parent;     // Need to GC not deleted session before any user code stopped using of this object

        ssh_channel_callbacks_struct _callbacks;

        OnEOFCallback _onEOFCallback;
        OnCloseCallback _onCloseCallback;
        OnSignalCallback _onSignalCallback;
        OnExitStatusCallback _onExitStatusCallback;
        OnExitSignalCallback _onExitSignalCallback;
        OnAuthAgentRequestCallback _onAuthAgentRequestCallback;
        OnX11RequestCallback _onX11RequestCallback;
        OnDataCallback _onDataCallback;
        OnPtyRequestCallback _onPtyRequestCallback;
        OnShellRequestCallback _onShellRequestCallback;
        OnPtyWindowChangeRequestCallback _onPtyWindowChangeRequestCallback;
        OnExecRequestCallback _onExecRequestCallback;
        OnEnvRequestCallback _onEnvRequestCallback;
        OnSubsystemRequestCallback _onSubsystemRequestCallback;

        void _dispose(bool fromDtor) {
            if (this._channel !is null) {
                ssh_channel_free(this._channel);

                if (!fromDtor) {
                    this._parent.freeChannel(this);
                }

                this._channel = null;
                this._parent = null;
            }
        }
    }
}

private {
    extern(C) int nativeOnData(ssh_session session, ssh_channel channel, void *data, uint len, 
            int is_stderr, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj._onDataCallback is null) {
            return SSH_ERROR;
        }

        try {
            return channelObj._onDataCallback(channelObj, data[0 .. len], 
                is_stderr == 0 ? false : true);
        } catch (Exception) {
            return SSH_ERROR;
        }
    }

    extern(C) void nativeOnEOFCallback(ssh_session session, ssh_channel channel, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onEOFCallback is null) {
            return;
        }

        channelObj._onEOFCallback(channelObj);
    }

    extern(C) void nativeOnCloseCallback(ssh_session session, ssh_channel channel, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onCloseCallback is null) {
            return;
        }

        channelObj._onCloseCallback(channelObj);
    }

    extern(C) void nativeOnSignalCallback(ssh_session session, ssh_channel channel, const char* signal,
            void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onSignalCallback is null) {
            return;
        }

        channelObj._onSignalCallback(channelObj, fromStrZ(signal));
    }

    extern(C) void nativeOnExitStatusCallback(ssh_session session, ssh_channel channel, int exit_status,
            void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onExitStatusCallback is null) {
            return;
        }
        
        channelObj._onExitStatusCallback(channelObj, exit_status);
    }

    extern(C) void nativeOnExitSignalCallback(ssh_session session, ssh_channel channel, const char* signal,
            int core, const char* errmsg, const char* lang, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onExitSignalCallback is null) {
            return;
        }

        channelObj._onExitSignalCallback(channelObj, fromStrZ(signal), core == 0 ? false : true,
            fromStrZ(errmsg), fromStrZ(lang));
    }

    extern(C) int nativeOnPtyRequestCallback(ssh_session session, ssh_channel channel, 
            const char* term, int width, int height, int pxwidth, int pxheight, void *userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj._onPtyRequestCallback is null) {
            return -1;
        }

        try {
            auto result = channelObj._onPtyRequestCallback(channelObj, fromStrZ(term), width,
                height, pxwidth, pxheight);
            return result ? 0 : -1;
        } catch(Exception) {
            return -1;
        }
    }

    extern(C) int nativeOnShellRequestCallback(ssh_session session, ssh_channel channel,
            void *userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj._onShellRequestCallback is null) {
            return 1;
        }

        try {
            auto result = channelObj._onShellRequestCallback(channelObj);
            return result ? 0 : 1;
        } catch(Exception) {
            return 1;
        }
    }

    extern(C) void nativeOnAuthAgentRequestCallback(ssh_session session, ssh_channel channel, 
            void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onAuthAgentRequestCallback is null) {
            return;
        }

        channelObj._onAuthAgentRequestCallback(channelObj);
    }

    extern(C) void nativeOnX11tRequestCallback(ssh_session session, ssh_channel channel, 
            int single_connection, const char *auth_protocol, const char *auth_cookie, 
            uint screen_number, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj is null || channelObj._onX11RequestCallback is null) {
            return;
        }

        channelObj._onX11RequestCallback(channelObj, single_connection == 0 ? false : true,
                fromStrZ(auth_protocol), fromStrZ(auth_cookie), screen_number);
    }

    extern(C) int nativeOnPtyWindowChangeRequestCallback(ssh_session session, ssh_channel channel, 
            int width, int height, int pxwidth, int pxheight, void *userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj._onPtyWindowChangeRequestCallback is null) {
            return -1;
        }

        try {
            auto result = channelObj._onPtyWindowChangeRequestCallback(channelObj, width, height, 
                pxwidth, pxheight);
            return result ? 0 : -1;
        } catch(Exception) {
            return -1;
        }
    }

    extern(C) int nativeOnExecRequestCallback(ssh_session session, ssh_channel channel,
            const char* command, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj._onExecRequestCallback is null) {
            return 1;
        }

        try {
            auto result = channelObj._onExecRequestCallback(channelObj, fromStrZ(command));
            return result ? 0 : 1;
        } catch(Exception) {
            return -1;
        }
    }

    extern(C) int nativeOnEnvRequestCallback(ssh_session session, ssh_channel channel,
            const char* env_name, const char* env_value, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;

        if (channelObj._onEnvRequestCallback is null) {
            return 1;
        }

        try {
            auto result = channelObj._onEnvRequestCallback(channelObj, fromStrZ(env_name),
                fromStrZ(env_value));
            return result ? 0 : 1;
        } catch (Exception) {
            return 1;
        }
    }

    extern(C) int nativeOnSubsystemRequestCallback(ssh_session session, ssh_channel channel,
            const char* subsystem, void* userdata) {
        auto channelObj = cast(SSHChannel) userdata;
        
        if (channelObj._onSubsystemRequestCallback is null) {
            return 1;
        }
        
        try {
            auto result = channelObj._onSubsystemRequestCallback(channelObj, fromStrZ(subsystem));
            return result ? 0 : 1;
        } catch (Exception) {
            return 1;
        }
    }
}
