module authentication;

import core.stdc.string : memset;
import std.stdio;
import std.algorithm.searching;
import std.exception;

import libssh.session;
import libssh.utils;
import libssh.errors;

AuthState authenticateKbdint(SSHSession session, string password) {
    auto err = session.userauthKeyboardInteractive(null);
    while (err == AuthState.Info) {
        auto name = session.userauthKeyboardInteractiveGetName();
        auto instruction = session.userauthKeyboardInteractiveGetInstruction();
        auto n = session.userauthKeyboardInteractiveGetNPrompts();

        if (name !is null && name.length > 0) {
            stdout.writefln("%s", name);
        }

        if (instruction !is null && instruction.length > 0) {
            stdout.writefln("%s", instruction);
        }

        for (int i = 0; i < n; i++) {
            bool echo;
            auto prompt = session.userauthKeyboardInteractiveGetPrompt(i, echo);

            if (echo) {
                stdout.writefln("%s", prompt);

                auto buffer = stdin.readln()[0 .. $ - 1];
                session.userauthKeyboardInteractiveSetAnswer(i, buffer);
            } else {
                string answer;
                char[] buffer;
                scope(exit) if (buffer !is null) memset(buffer.ptr, 0, buffer.length);

                if (password !is null && prompt.canFind("Password:")) {
                    answer = password;
                } else {
                    buffer = getPassword!(128)(prompt, false, false);
                    if (buffer is null) {
                        throw new SSHException("Error while reading password from user");
                    }
                    answer = assumeUnique(buffer);
                }

                session.userauthKeyboardInteractiveSetAnswer(i, answer);
            }
        }
        err = session.userauthKeyboardInteractive(null);
    }
    return err;
}

AuthState authenticateConsole(SSHSession session) {
    // Try to authenticate
    AuthState rc = session.userauthNone(null);

    auto method = session.userauthList(null);

    while (rc != AuthState.Success) {
        if ((method & AuthMethod.GSSAPIMic) != 0) {
            rc = session.userauthGSSAPI();
            if (rc == AuthState.Success) {
                break;
            }
        }

        // Try to authenticate with public key first
        if ((method & AuthMethod.PublicKey) != 0) {
            rc = session.userauthPublicKeyAuto(null, null);
            if (rc == AuthState.Success) {
                break;
            }
        }

        // Try to authenticate with keyboard interactive";
        if ((method & AuthMethod.Interactive) != 0) {
            rc = authenticateKbdint(session, null);
            if (rc == AuthState.Success) {
                break;
            }
        }

        auto password = getPassword!(128)("Password: ", false, false);
        if (password is null) {
            throw new SSHException("Error while reading password from user");
        }

        // Try to authenticate with password
        if ((method & AuthMethod.Password) != 0) {
            rc = session.userauthPassword(null, assumeUnique(password));
            if (rc == AuthState.Success) {
                break;
            }
        }
        memset(password.ptr, 0, password.length);
    }

    auto banner = session.issueBanner();
    if (banner !is null) {
        stdout.writefln("%s", banner);
    }
    return rc;
}
