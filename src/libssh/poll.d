module libssh.poll;

import libssh.c_bindings.libssh;
import libssh.c_bindings.poll;
import libssh.errors;
import libssh.utils;
import libssh.session;

enum PollEvents : short {
    In = POLLIN,
    Pro = POLLPRI,
    Out = POLLOUT,
}

class SSHEvent : Disposable {
    alias EventCallback = bool delegate(socket_t fd, PollEvents revents);

    void addFd(socket_t fd, PollEvents events, EventCallback cb) {
        this._eventCallbacks[fd] = cb;
        scope(failure) this._eventCallbacks.remove(fd);

        auto rc = ssh_event_add_fd(this._event, fd, events, &nativeEventCallback, 
            cast(void*) &this._eventCallbacks[fd]);
        checkForRCError(rc, rc);
    }

    void removeFd(socket_t fd) {
        scope(exit) this._eventCallbacks.remove(fd);
        auto rc = ssh_event_remove_fd(this._event, fd);
        checkForRCError(rc, rc);
    }

    void addSession(SSHSession session) {
        auto rc = ssh_event_add_session(this._event, session._session);
        checkForRCError(rc, rc);
    }

    void removeSession(SSHSession session) {
        auto rc = ssh_event_remove_session(this._event, session._session);
        checkForRCError(rc, rc);
    }

    void doPoll(int timeout) {
        auto rc = ssh_event_dopoll(this._event, timeout);
        checkForRCError(rc, rc);
    }

    this() {
        auto event = ssh_event_new();
        if (event is null) {
            throw new SSHException("Error while creating new event");
        }
        this(event);
    }

    ~this() {
        this._dispose(true);
    }

    override void dispose() {
        this._dispose(false);
    }

    private {
        void _dispose(bool fromDtor) {
            if (this._event !is null) {
                ssh_event_free(this._event);
                this._event = null;
            }
        }

        this(ssh_event event) {
            this._event = event;
        }

        ssh_event _event;
        EventCallback[socket_t] _eventCallbacks;
    }
}

private {
    extern(C) int nativeEventCallback(socket_t fd, int revents, void *userdata) {
        auto cb = cast(SSHEvent.EventCallback*) userdata;

        try {
            return (*cb)(fd, cast(PollEvents) revents) ? SSH_OK : SSH_ERROR;
        } catch (Exception) {
            return SSH_ERROR;
        }
    }
}
