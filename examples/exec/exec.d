module exec;

import std.stdio;

import libssh.session;
import libssh.channel;
import libssh.errors;

import connect_ssh;

int main(string[] argv) {
    scope(exit) sshFinalize();

    SSHSession session = sessionConnect("localhost", null, LogVerbosity.NoLog);
    if (session is null) {
        return -1;
    }
    scope(exit) session.dispose();

    try {
        auto channel = session.newChannel();
        scope(exit) channel.dispose();

        channel.openSession();
        scope(exit) channel.close();

        channel.requestExec("lsof");
        scope(exit) channel.sendEof();

        char[256] buffer;
        auto nbytes = channel.read(buffer, false);
        while (nbytes > 0) {
            stdout.write(buffer[0 .. nbytes]);
            nbytes = channel.read(buffer, false);
        }
    } catch (SSHException sshException) {
        stderr.writefln("SSH exception. Code = %d, Message:\n%s\n",
            sshException.errorCode, sshException.msg);
        return -1;
    }

    return 0;
}