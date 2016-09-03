module libssh.message;

import libssh.c_bindings.libssh;
import libssh.c_bindings.server;
import libssh.utils;
import libssh.errors;
import libssh.session;
import libssh.key;

class SSHMessage : Disposable {

    @property int type() {
        auto rc = ssh_message_type(this._message);
        if (rc < 0) {
            throw new SSHException(this._parent._session);
        }
        return rc;
    }

    @property int subtype() {
        auto rc = ssh_message_subtype(this._message);
        if (rc < 0) {
            throw new SSHException(this._parent._session);
        }
        return rc;
    }



    @property string authUser() {
        auto result = ssh_message_auth_user(this._message);
        if (result is null) {
            throw new SSHException(this._parent._session);
        }
        return fromStrZ(result);
    }

    @property string authPassword() {
        auto result = ssh_message_auth_password(this._message);
        if (result is null) {
            throw new SSHException(this._parent._session);
        }
        return fromStrZ(result);
    }    

    @property SSHKey authPubKey() {
        auto result = ssh_message_auth_pubkey(this._message);
        return result is null ? null : new SSHKey(result);
    }

    @property void authMethods(AuthMethod m) {
        ssh_message_auth_set_methods(this._message, cast(int) m);
    }

    void replyDefault() {
        auto rc = ssh_message_reply_default(this._message);
        if (rc != SSH_OK) {
            throw new SSHException(this._parent._session);
        }
    }


    override void dispose() {
        this._dispose(false);
    }
    
    ~this() {
        this._dispose(true);
    }
    
    package {
        this(SSHSession parent, ssh_message message) {
            this._parent = parent;
            this._message = message;
        }

        SSHSession _parent;
        ssh_message _message;
    }
    
    private {
        void _dispose(bool fromDtor) {
            if (this._message !is null) {
                ssh_message_free(this._message);
                this._message = null;
            }
        }
    }
}
