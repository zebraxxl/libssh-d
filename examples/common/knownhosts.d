module knownhosts;

import std.stdio;
import std.string;

import libssh.session;
import libssh.key;
import libssh.utils;

bool verifyKnownhost(SSHSession session) {
    auto state = session.serverKnownState();

    auto srvPubKey = session.publicKey();
    scope(exit) srvPubKey.dispose();

    auto hash = srvPubKey.getHash(PublicKeyHashType.SHA1);

    final switch (state) {
        case ServerKnownState.Ok:
            return true;

        case ServerKnownState.Changed:
            stderr.writeln("Host key for server changed : server's one is now :");
            printHexa("Public key hash", hash);
            stderr.writeln("For security reason, connection will be stopped");
            return false;

        case ServerKnownState.FoundOther:
            stderr.writeln("The host key for this server was not found but an other type of key exists.");
            stderr.writeln("An attacker might change the default server key to confuse your client into thinking the key does not exist");
            stderr.writeln("We advise you to rerun the client with -d or -r for more safety.");
            return false;

        case ServerKnownState.FileNotFound:
            stderr.writeln("Could not find known host file. If you accept the host key here,");
            stderr.writeln("the file will be automatically created.");
            goto case ServerKnownState.NotKnown;

        case ServerKnownState.NotKnown:
            auto hexa = getHexa(hash);
            stderr.writeln("The server is unknown. Do you trust the host key ?");
            stderr.writefln("Public key hash: %s", hexa);
            if (stdin.readln().toLower() != "yes\n") {
                return false;
            }
            stderr.writeln("This new key will be written on disk for further usage. do you agree ?");
            if (stdin.readln().toLower() != "yes\n") {
                return false;
            }
            session.writeKnownHost();
            return true;
    }
}