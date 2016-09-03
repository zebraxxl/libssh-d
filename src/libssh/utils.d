module libssh.utils;

import core.stdc.string : memset, strlen, memcpy;

import libssh.c_bindings.libssh;

interface Disposable {
    void dispose();
}

void printHexa(string description, const ubyte[] what) {
    ssh_print_hexa(toStrZ(description), what.ptr, what.length);
}

string getHexa(const ubyte[] what) {
    auto result = ssh_get_hexa(what.ptr, what.length);
    scope(exit) ssh_string_free_char(result);
    return copyFromStrZ(result);
}

char[] getPassword(size_t bufferSize)(string prompt, bool echo, bool verify) {
    char[bufferSize] buffer;
    memset(buffer.ptr, 0, bufferSize);
    scope(exit) memset(buffer.ptr, 0, bufferSize);

    auto rc = ssh_getpass(toStrZ(prompt), buffer.ptr, bufferSize, echo ? 1 : 0, verify ? 1 : 0);
    if (rc < 0) {
        return null;
    }
    auto result = new char[strlen(buffer.ptr)];
    memcpy(result.ptr, buffer.ptr, result.length);
    return result;
}

string sshVersion(int reqVersion) {
    auto result = ssh_version(reqVersion);
    return fromStrZ(result);
}

package {
    string fromStrZ(const(char)* v) {
        if (v is null) {
            return null;
        }
        
        import core.stdc.string : strlen;
        return cast(string) v[0 .. strlen(v)];
    }
    
    string fromStrZ(const(char)* v, size_t len) {
        if (v is null) {
            return null;
        }
        
        return cast(string) v[0 .. len];
    }
    
    string copyFromStrZ(const(char)* v) {
        if (v is null) {
            return null;
        }
        
        import core.stdc.string : strlen, memcpy;
        
        auto len = strlen(v);
        char[] result = new char[len];
        memcpy(result.ptr, v, len);
        return cast(string) result;
    }
    
    const(char)* toStrZ(string s) {
        if (s is null) {
            return null;
        }
        
        import std.string : toStringz;
        return toStringz(s);
    }

    char* copyToStrZ(string s) {
        import core.stdc.string : strlen, memcpy;
        char[] result = new char[s.length];
        memcpy(result.ptr, s.ptr, s.length);
        return result.ptr;
    }
}
