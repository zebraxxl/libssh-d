module libssh.scp;

import libssh.c_bindings.libssh;
import libssh.errors;
import libssh.utils;
import libssh.session;

enum SCPMode : int {
    Write = SSH_SCP_WRITE,
    Read = SSH_SCP_READ,
    Recursive = SSH_SCP_RECURSIVE,
}

enum SCPRequest : int {
    NewDir = ssh_scp_request_types.SSH_SCP_REQUEST_NEWDIR,
    NewFile = ssh_scp_request_types.SSH_SCP_REQUEST_NEWFILE,
    EOF = ssh_scp_request_types.SSH_SCP_REQUEST_EOF,
    EndDir = ssh_scp_request_types.SSH_SCP_REQUEST_ENDDIR,
    Warning = ssh_scp_request_types.SSH_SCP_REQUEST_WARNING,
}

class SSHSCP : Disposable {

    @property string requestFilename() {
        auto result = ssh_scp_request_get_filename(this._scp);
        checkForNullError(result, "Error while getting request file name");
        return copyFromStrZ(result);
    }

    @property uint requestPermissions() {
        auto result = ssh_scp_request_get_permissions(this._scp);
        if (result < 0) {
            throw new SSHException(result);
        }
        return cast(uint) result;
    }

    @property size_t requestSize() {
        return ssh_scp_request_get_size(this._scp);
    }

    @property ulong requestSize64() {
        return ssh_scp_request_get_size64(this._scp);
    }

    @property string requestWarning() {
        auto result = ssh_scp_request_get_warning(this._scp);
        checkForNullError(result, "Error while getting request warning");
        return copyFromStrZ(result);
    }

    void acceptRequest() {
        auto rc = ssh_scp_accept_request(this._scp);
        checkForRCError(rc, rc, "Error while accept request");
    }
    
    void denyRequest(string reason) {
        auto rc = ssh_scp_deny_request(this._scp, toStrZ(reason));
        checkForRCError(rc, rc, "Error while deny request");
    }

    void leaveDirectory() {
        auto rc = ssh_scp_leave_directory(this._scp);
        checkForRCError(rc, rc, "Error while leave directory");
    }

    SCPRequest pullRequest() {
        auto rc = ssh_scp_pull_request(this._scp);
        if (rc < 0) {
            throw new SSHException(rc, "Error while pull request");
        }
        return cast(SCPRequest) rc;
    }

    void pushDirectory(string dirName, int mode) {
        auto rc = ssh_scp_push_directory(this._scp, toStrZ(dirName), mode);
        checkForRCError(rc, rc, "Error while pushing directory");
    }

    void pushFile(string fileName, size_t size, uint mode) {
        auto rc = ssh_scp_push_file(this._scp, toStrZ(fileName), size, cast(uint) mode);
        checkForRCError(rc, rc, "Error while pushing file");
    }

    void pushFile64(string fileName, ulong size, uint mode) {
        auto rc = ssh_scp_push_file64(this._scp, toStrZ(fileName), size, cast(uint) mode);
        checkForRCError(rc, rc, "Error while pushing file");
    }

    int read(void[] buffer) {
        auto rc = ssh_scp_read(this._scp, buffer.ptr, buffer.length);
        if (rc < 0) {
            throw new SSHException(rc, "Error while reading");
        }
        return rc;
    }

    void write(const void[] buffer) {
        auto rc = ssh_scp_write(this._scp, buffer.ptr, buffer.length);
        checkForRCError(rc, rc, "Error while writing");
    }

    void init() {
        auto rc = ssh_scp_init(this._scp);
        checkForRCError(rc, rc, "Error while initializing scp");
    }

    void close() {
        auto rc = ssh_scp_close(this._scp);
        checkForRCError(rc, rc, "Error while closing");
    }
    
    ~this() {
        this._dispose(true);
    }
    
    override void dispose() {
        this._dispose(false);
    }

    package {
        this(SSHSession parent, ssh_scp scp) {
            this._session = parent;
            this._scp = scp;
        }
    }
    
    private {
        void _dispose(bool fromDtor) {
            if (this._scp !is null) {
                ssh_scp_free(this._scp);
                this._session = null;
                this._scp = null;
            }
        }

        SSHSession _session;
        ssh_scp _scp;
    }
}
