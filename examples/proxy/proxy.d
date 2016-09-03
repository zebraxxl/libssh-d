module proxy;

import std.stdio;
import std.functional;
import std.format;
import std.string;

import libssh.session;
import libssh.channel;
import libssh.errors;
import libssh.server;
import libssh.poll;

enum auto USER = "myuser";
enum auto PASSWORD = "mypassword";

bool authentificated = false;
int tries = 0;
bool error = false;
SSHChannel chan = null;
string username;
GSSAPICreds clientCreds = 0;

AuthState authPassword(SSHSession session, string user, string password) {
    stdout.writefln("Authenticating user %s pwd %s\n",user, password);
    if (user == USER && password == PASSWORD) {
        authentificated = true;
        stdout.writefln("Authenticated");
        return AuthState.Success;
    }
    if (tries >= 3) {
        stdout.writefln("Too many authentication tries");
        session.disconnect();
        error = true;
        return AuthState.Denied;
    }
    tries++;
    return AuthState.Denied;
}

version(LIBSSH_WITH_GSSAPI) {
    AuthState authGSSAPIMic(SSHSession session, string user, string principal) {
        clientCreds = session.gssapiGetCreds;
        stdout.writefln("Authenticating user %s with gssapi principal %s",user, principal);
        if (clientCreds !is null) {
            stdout.writefln("Received some gssapi credentials");
        } else {
            stdout.writefln("Not received any forwardable creds");
        }
        stdout.writefln("authenticated");
        authentificated = true;
        username = principal.dup;
        return AuthState.Success;
    }
}

bool ptyRequest(SSHChannel channel, string term, int width, int height, int pxWidth, int pxHeight) {
    stdout.writeln("allocated terminal");
    return true;
}

bool shellRequest(SSHChannel channel) {
    stdout.writeln("allocated shell");
    return true;
}

SSHChannel newSessionChannel(SSHSession session) {
    if (chan !is null) {
        return null;
    }
    chan = session.newChannel();
    chan.onPtyRequestCallback = toDelegate(&ptyRequest);
    chan.onShellRequestCallback = toDelegate(&shellRequest);
    return chan;
}

// TODO: options parsing

int main(string[] argv) {
    scope(exit) sshFinalize();

    try {
        auto sshBind = new SSHBind();
        scope(exit) sshBind.dispose();

        auto session = new SSHSession();
        scope(exit) session.dispose();
        
        sshBind.rsaKey = "sshd_rsa";
        
        // TODO: options parsing
        sshBind.bindPort = 2222;

        sshBind.listen();

        sshBind.accept(session);

        session.serverAuthPasswordCallback = toDelegate(&authPassword);
        session.serverChannelOpenRequestCallback = toDelegate(&newSessionChannel);
        version(LIBSSH_WITH_GSSAPI) {
            session.ServerAuthGSSAPIMicCallback = toDelegate(&authGSSAPIMic);
        }

        session.handleKeyExchange();
        version(LIBSSH_WITH_GSSAPI) {
            session.authMethods = AuthMethod.Password | AuthMethod.GSSAPIMic;
        } else {
            session.authMethods = AuthMethod.Password;
        }

        auto mainLoop = new SSHEvent();
        scope(exit) mainLoop.dispose();
        mainLoop.addSession(session);

        while (!(authentificated && chan !is null)) {
            if (error) {
                break;
            }

            mainLoop.doPoll(-1);
        }

        if (error) {
            stdout.writeln("Error, exiting loop");
            return 1;
        } else {
            stdout.writeln("Authenticated and got a channel");
        }
        if (clientCreds == 0) {
            chan.write("Sorry, but you do not have forwardable tickets. Try again with -K\r\n");
            stdout.writeln("Sorry, but you do not have forwardable tickets. Try again with -K");
            session.disconnect();
            return 1;
        }

        chan.write(format("Hello %s, welcome to the Sample SSH proxy.\r\nPlease select your destination: ",
                username));

        string host = "";
        int i = 0;
        do {
            char[2048] buf;
            i = chan.read(buf, false);
            if (i > 0) {
                chan.write(buf[0 .. i]);
                if (host.length + i < 128) {
                    host ~= buf[0 .. i];
                }
                auto lfIndex = host.indexOf('\x0d');
                if (lfIndex >= 0) {
                    host = host[0 .. lfIndex];
                    chan.write("\n");
                    break;
                }
            } else {
                stdout.writefln("Error: %s", session.lastError);
                return 1;
            }
        } while (i > 0);

        auto buf = format("Trying to connect to \"%s\"\r\n", host);
        chan.write(buf);
        stdout.write(buf);

        auto clientSession = new SSHSession();
        scope(exit) clientSession.dispose();

        /* ssh servers expect username without realm */
        auto ptr = username.indexOf('@');
        if (ptr >= 0) {
            username = username[0 .. ptr];
        }

        clientSession.host = host;
        clientSession.user = username;
        version(LIBSSH_WITH_GSSAPI) {
            clientSession.gssapiCreds = clientCreds;
        }
        clientSession.connect();

        auto rc = clientSession.userauthNone(null);
        if (rc == AuthState.Success) {
            stdout.writeln("Authenticated using method none");
        } else {
            rc = clientSession.userauthGSSAPI();
            if (rc != AuthState.Success) {
                stdout.writefln("GSSAPI Authentication failed: %s", clientSession.lastError);
                return 1;
            }
        }

        buf = "Authentication success\r\n";
        stdout.write(buf);
        chan.write(buf);
        clientSession.disconnect();
        session.disconnect();

    } catch (SSHException sshException) {
        stderr.writefln("SSH exception. Code = %d, Message:\n%s\n",
            sshException.errorCode, sshException.msg);
        return -1;
    }
    return 0;
}
