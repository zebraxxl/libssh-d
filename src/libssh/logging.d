module libssh.logging;

import core.sync.rwmutex;
import std.algorithm.mutation;
import std.algorithm.searching;

import libssh.c_bindings.libssh;
import libssh.errors;
import libssh.utils;

enum LogLevel : int {
    NoLog = SSH_LOG_NOLOG,
    Rare = SSH_LOG_RARE,
    Warning = SSH_LOG_WARNING,
    Protocol = SSH_LOG_PROTOCOL,
    Packet = SSH_LOG_PACKET,
    Functions = SSH_LOG_FUNCTIONS,
}

alias LoggingCallbackDelegate = void delegate(LogLevel ll, string function_, string message);
alias LoggingCallbackFunction = void function(LogLevel ll, string function_, string message);

bool addLoggingHandler(LoggingCallbackDelegate d) {
    synchronized(_handlersLock.writer) {
        if (!_loggingDelegates.canFind(d)) {
            _loggingDelegates ~= d;
            return true;
        }
        return false;
    }
}

bool addLoggingHandler(LoggingCallbackFunction d) {
    synchronized(_handlersLock.writer) {
        if (!_loggingFunctions.canFind(d)) {
            _loggingFunctions ~= d;
            return true;
        }
        return false;
    }
}

void removeLoggingHandler(LoggingCallbackDelegate d) {
    synchronized(_handlersLock.writer) {
        _loggingDelegates = remove!(a => a == d)(_loggingDelegates);
    }
}

void removeLoggingHandler(LoggingCallbackFunction d) {
    synchronized(_handlersLock.writer) {
        _loggingFunctions = remove!(a => a == d)(_loggingFunctions);
    }
}

@property LogLevel logLevel() {
    return cast(LogLevel) ssh_get_log_level();
}

@property void logLevel(LogLevel ll) {
    auto rc = ssh_set_log_level(ll);
    if (rc != SSH_OK) {
        throw new SSHException(rc);
    }
}

private {
    __gshared ReadWriteMutex _handlersLock;

    __gshared LoggingCallbackDelegate[] _loggingDelegates;
    __gshared LoggingCallbackFunction[] _loggingFunctions;

    shared static this() {
        _handlersLock = new ReadWriteMutex();
        _loggingDelegates = [];
        _loggingFunctions = [];
    }

    extern(C) void nativeLoggingCallback(int priority, const char* function_, const char* buffer,
            void*) {
        synchronized (_handlersLock.reader) {
            foreach(h; _loggingDelegates) {
                h(cast(LogLevel) priority, fromStrZ(function_), fromStrZ(buffer));
            }
            foreach(h; _loggingFunctions) {
                h(cast(LogLevel) priority, fromStrZ(function_), fromStrZ(buffer));
            }
        }
    }
}
