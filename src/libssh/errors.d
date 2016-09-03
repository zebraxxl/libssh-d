module libssh.errors;

import std.format;

import libssh.c_bindings.libssh;
import libssh.c_bindings.sftp;
import libssh.c_bindings.server;
import libssh.utils;

enum SSHError : int {
    NoError = ssh_error_types_e.SSH_NO_ERROR,
    RequestDenied = ssh_error_types_e.SSH_REQUEST_DENIED,
    Fatal = ssh_error_types_e.SSH_FATAL,
    EIntr = ssh_error_types_e.SSH_EINTR,

    Error = SSH_ERROR,
    Again = SSH_AGAIN,
    EOF = SSH_EOF
}

enum SFTPError {
    Ok =  SSH_FX_OK,
    Eof =  SSH_FX_EOF,
    NoSuchFile =  SSH_FX_NO_SUCH_FILE,
    PermissionDenied =  SSH_FX_PERMISSION_DENIED,
    Failure =  SSH_FX_FAILURE,
    BadMessage =  SSH_FX_BAD_MESSAGE,
    NoConnection =  SSH_FX_NO_CONNECTION,
    ConnectionLost =  SSH_FX_CONNECTION_LOST,
    OpUnsupported =  SSH_FX_OP_UNSUPPORTED,
    InvalidHandle =  SSH_FX_INVALID_HANDLE,
    NoSuchPath =  SSH_FX_NO_SUCH_PATH,
    FileAlreadyExists =  SSH_FX_FILE_ALREADY_EXISTS,
    WriteProtect =  SSH_FX_WRITE_PROTECT,
    NoMedia =  SSH_FX_NO_MEDIA,

    Unknown
}

class SSHException : Exception {
    @property SSHError errorCode() {
        return cast(SSHError) this._errorCode;
    }

    this(string errorMessage) {
        this._errorCode = SSHError.Fatal;
        super(errorMessage);
    }

    this(int errorCode) {
        this._errorCode = errorCode;
        super(format("SSH error with code %d", errorCode));
    }

    this(int errorCode, string errorMessage) {
        this._errorCode = errorCode;
        super(errorMessage);
    }

    package this(ssh_session session) {
        this._errorCode = ssh_get_error_code(session);
        super(copyFromStrZ(ssh_get_error(session)));
    }

    package this(ssh_bind bind) {
        this._errorCode = ssh_get_error_code(bind);
        super(copyFromStrZ(ssh_get_error(bind)));
    }

    private int _errorCode;
}

class SFTPException : SSHException {
    @property sftpErrorCode() {
        return cast(SFTPError) this._sftpErrorCode;
    }

    this(int errorCode, ssh_session session) {
        super(session);
        _sftpErrorCode = errorCode;
    }

    private int _sftpErrorCode;
}


package {
    void checkForRCError(T, CtorArgs...)(T rc, CtorArgs args) {
        if (rc != SSH_OK) {
            throw new SSHException(args);
        }
    }

    void checkForNullError(T, CtorArgs...)(T rc, CtorArgs args) {
        if (rc is null) {
            throw new SSHException(args);
        }
    }
}
