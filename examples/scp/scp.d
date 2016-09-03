module scp;

import core.stdc.stdlib;
import std.stdio;
import std.string;
import std.file;
import std.path;

import libssh.session;
import libssh.scp;
import libssh.utils;
import libssh.errors;

import connect_ssh;

static string[] sources;
static string destination;
static int verbosity = 0;

struct location {
    bool isSSH;
    string user;
    string host;
    string path;
    SSHSession session;
    SSHSCP scp;
    File file;
}

enum Flag {
    READ,
    WRITE
}

void usage(string argv0) {
    stderr.writefln("Usage : %s [options] [[user@]host1:]file1 ... ", argv0);
    stderr.writeln("                            [[user@]host2:]destination");
    stderr.writefln("sample scp client - libssh-%s", sshVersion(0));
    exit(0);
}

bool opts(string[] argv) {
    int i = 1;
    while (i < argv.length) {
        if (argv[i][0] != '-') {
            break;
        }
        if (argv[i] == "-v") {
            verbosity++;
        } else {
            stderr.writeln("unknown option %s", argv[i][1 .. $]);
            usage(argv[0]);
            return false;
        }
        i++;
    }

    auto sourcesCount = cast(int) argv.length - i - 1;
    if (sourcesCount < 1) {
        usage(argv[0]);
        return false;
    }

    sources = argv[i .. $ - 1];
    destination = argv[$ - 1];

    return true;
}

location parseLocation(string loc) {
    location result = location.init;

    auto colonIndex = loc.indexOf(':');
    if (colonIndex >= 0) {
        result.isSSH = true;
        result.path = loc[colonIndex + 1 .. $];
        auto atIndex = loc.indexOf('@');
        if (atIndex >= 0) {
            result.host = loc[atIndex + 1 .. colonIndex];
            result.user = loc[0 .. atIndex];
        } else {
            result.host = loc[0 .. colonIndex];
        }
    } else {
        result.isSSH = false;
        result.path = loc;
    }
    return result;
}

bool openLocation(ref location loc, Flag flag) {
    try {
        if (loc.isSSH && flag == Flag.WRITE) {
            loc.session = sessionConnect(loc.host, loc.user, cast(LogVerbosity) verbosity);
            if (loc.session is null) {
                return false;
            }

            loc.scp = loc.session.newScp(SCPMode.Write, loc.path);
            scope(failure) {
                loc.scp.dispose();
                loc.scp = null;
            }

            loc.scp.init();
            return true;
        } else if (loc.isSSH && flag == Flag.READ) {
            loc.session = sessionConnect(loc.host, loc.user, cast(LogVerbosity) verbosity);
            if (loc.session is null) {
                return false;
            }
            
            loc.scp = loc.session.newScp(SCPMode.Read, loc.path);
            scope(failure) {
                loc.scp.dispose();
                loc.scp = null;
            }
            
            loc.scp.init();
            return true;
        } else {
            if (isDir(loc.path)) {
                chdir(loc.path);
                return true;
            }

            loc.file = File(loc.path, flag == Flag.READ ? "r" : "w");
            return true;
        }
    } catch (SSHException sshException) {
        stderr.writefln("SSH exception. Code = %d, Message:\n%s\n",
            sshException.errorCode, sshException.msg);
        return false;
    } catch (Exception exception) {
        stderr.writefln("Exception. Message:\n%s\n", exception.msg);
        return false;
    }
}

/** @brief copies files from source location to destination
 * @param src source location
 * @param dest destination location
 * @param recursive Copy also directories
 */
void doCopy(ref location src, ref location dest, bool recursive) {
    /* recursive mode doesn't work yet */

    ulong size;
    uint mode;
    string fileName;

    if (!src.isSSH) {
        size = getSize(src.path);
        mode = getAttributes(src.path) & 0x1ff;
        fileName = baseName(src.path);
    } else {
        size = 0;
        SCPRequest r;
        do {
            r = src.scp.pullRequest();
            if (r == SCPRequest.NewDir) {
                src.scp.denyRequest("Not in recursive mode");
                continue;
            }

            if (r == SCPRequest.NewFile) {
                size = src.scp.requestSize64();
                fileName = src.scp.requestFilename();
                mode = src.scp.requestPermissions();
                break;
            }
        } while (r != SCPRequest.NewFile);
    }

    if (dest.isSSH) {
        dest.scp.pushFile64(src.path, size, mode);
    } else {
        if (!dest.file.isOpen()) {
            dest.file = File(fileName, "wb");
        }
        if (src.isSSH) {
            src.scp.acceptRequest();
        }
    }

    ulong total = 0;
    ubyte[16384] buffer;
    ubyte[] outBuffer;

    do {
        size_t r;
        if (src.isSSH) {
            r = src.scp.read(buffer);
            if (r == 0) {
                break;
            }
            outBuffer = buffer[0 .. r];
        } else {
            outBuffer = src.file.rawRead(buffer);
            r = outBuffer.length;
            if (outBuffer.length == 0) {
                break;
            }
        }

        if (dest.isSSH) {
            dest.scp.write(outBuffer);
        } else {
            dest.file.rawWrite(outBuffer);
        }

        total += r;
    } while (total < size);

    stdout.writefln("wrote %d bytes", total);
}

int main(string[] argv) {
    scope(exit) sshFinalize();

    if (!opts(argv)) {
        return -1;
    }

    stdout.writefln("verbose = %d", verbosity);

    try {
        auto dest = parseLocation(destination);
        if (!openLocation(dest, Flag.WRITE)) {
            return -1;
        }
        scope(exit) {
            if (dest.isSSH) {
                dest.scp.dispose();
                dest.session.dispose();
            } else {
                dest.file.close();
            }
        }

        for (int i = 0; i < sources.length; i++) {
            auto src = parseLocation(sources[i]);
            if (!openLocation(src, Flag.READ)) {
                return -1;
            }
            scope(exit) {
                if (src.isSSH) {
                    src.scp.dispose();
                    src.session.dispose();
                } else {
                    src.file.close();
                }
            }

            doCopy(src, dest, false);
        }

    } catch (SSHException sshException) {
        stderr.writefln("SSH exception. Code = %d, Message:\n%s\n",
            sshException.errorCode, sshException.msg);
        return -1;
    }

    return 0;
}
