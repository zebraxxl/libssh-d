module libssh.sftp;

import core.stdc.string : memcpy;

import libssh.c_bindings.libssh;
import libssh.c_bindings.sftp;
import libssh.c_bindings.ctypes;
import libssh.errors;
import libssh.utils;
import libssh.session;


struct SFTPStatVFS {
    // just copy sftp_statvfs_struct
    ulong f_bsize;   /** file system block size */
    ulong f_frsize;  /** fundamental fs block size */
    ulong f_blocks;  /** number of blocks (unit f_frsize) */
    ulong f_bfree;   /** free blocks in file system */
    ulong f_bavail;  /** free blocks for non-root */
    ulong f_files;   /** total file inodes */
    ulong f_ffree;   /** free file inodes */
    ulong f_favail;  /** free file inodes for to non-root */
    ulong f_fsid;    /** file system id */
    ulong f_flag;    /** bit mask of f_flag values */
    ulong f_namemax; /** maximum filename length */
}

struct TimesValue {
    long sec;
    long usec;
}

struct SFTPAttributes {
    string name;
    string longName; /* ls -l output on openssh, not reliable else */
    uint flags;     // TODO: enum
    ubyte type;
    ulong size;
    uint uid;
    uint gid;
    string owner; /* set if openssh and version 4 */
    string group; /* set if openssh and version 4 */
    uint permissions;
    ulong atime64;
    uint atime;
    uint atimeNSeconds;
    ulong createtime;
    uint createtimeNSeconds;
    ulong mtime64;
    uint mtime;
    uint mtimeNSeconds;
    string acl;
    uint extendedCount;
    string extendedType;
    string extendedData;
}


class SFTPDirectory : Disposable {
    @property bool eof() {
        return sftp_dir_eof(this._dir) == 0 ? false : true;
    }

    void readdir(out SFTPAttributes attrs) {
        auto result = sftp_readdir(this._session._sftpSession, this._dir);
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        convertAndFreeSftpAttributes(result, attrs);
    }

    void close() {
        auto rc = sftp_closedir(this._dir);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        this._dir = null;
        this._session = null;
    }

    ~this() {
        this._dispose(true);
    }

    override void dispose() {
        this._dispose(false);
    }

    private {
        void _dispose(bool fromDtor) {
            if (this._dir !is null) {
                sftp_closedir(this._dir);
                this._dir = null;
                this._session = null;
            }
        }

        this(SFTPSession session, sftp_dir dir) {
            this._session = session;
            this._dir = dir;
        }

        SFTPSession _session;
        sftp_dir _dir;
    }
}

class SFTPFile : Disposable {
    enum auto ReadAgain = int.min;
    enum auto WriteAgain = int.min;

    @property void blocking(bool v) {
        if (v) {
            sftp_file_set_blocking(this._file);
        } else {
            sftp_file_set_nonblocking(this._file);
        }
    }

    uint asyncReadBegin(uint len) {
        auto rc = sftp_async_read_begin(this._file, len);
        if (rc < 0) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        return cast(uint) rc;
    }
    
    /**
     * returns SFTPFile.ReadAgain in nonblocking mode
     **/
    int asyncRead(void[] buffer, uint id) {
        auto rc = sftp_async_read(this._file, buffer.ptr, cast(uint) buffer.length, id);
        if (rc == SSH_AGAIN) {
            return ReadAgain;
        }
        if (rc < 0) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        return rc;
    }

    /**
     * returns SFTPFile.ReadAgain in nonblocking mode
     **/
    size_t read(void[] buffer) {
        auto rc = sftp_read(this._file, buffer.ptr, cast(size_t) buffer.length);
        if (rc == SSH_AGAIN) {
            return ReadAgain;
        }
        if (rc < 0) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        return rc;
    }

    /**
     * returns SFTPFile.WriteAgain in nonblocking mode
     **/
    size_t write(const void[] buffer) {
        auto rc = sftp_write(this._file, buffer.ptr, cast(size_t) buffer.length);
        if (rc == SSH_AGAIN) {
            return WriteAgain;
        }
        if (rc < 0) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        return rc;
    }

    void rewind() {
        sftp_rewind(this._file);
    }

    void seek(uint newOffset) {
        auto rc = sftp_seek(this._file, newOffset);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
    }

    uint tell() {
        auto rc = sftp_tell(this._file);
        if (rc < 0) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        return rc;
    }

    ulong tell64() {
        auto rc = sftp_tell64(this._file);
        if (rc < 0) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        return rc;
    }

    void seek64(ulong newOffset) {
        auto rc = sftp_seek64(this._file, newOffset);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
    }

    void fstat(out SFTPAttributes attrs) {
        auto result = sftp_fstat(this._file);
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        convertAndFreeSftpAttributes(result, attrs);
    }

    SFTPStatVFS fstatVFS() {
        auto result = sftp_fstatvfs(this._file);
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        scope(exit) sftp_statvfs_free(result);

        SFTPStatVFS resultObj;
        memcpy(&resultObj, result, SFTPStatVFS.sizeof);
        return resultObj;
    }

    void close() {
        auto rc = sftp_close(this._file);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._session._sftpSession),
                this._session._session._session);
        }
        this._file = null;
    }

    ~this() {
        this._dispose(true);
    }

    override void dispose() {
        this._dispose(false);
    }

    private {
        this(SFTPSession session, sftp_file file) {
            this._session = session;
            this._file = file;
        }

        void _dispose(bool fromDtor) {
            if (this._file !is null) {
                sftp_close(this._file);
                this._file = null;
                this._session = null;
            }
        }

        SFTPSession _session;
        sftp_file _file;
    }
}

class SFTPSession : Disposable {
    @property uint extensionsCount() {
        return sftp_extensions_get_count(this._sftpSession);
    }

    @property int serverVersion() {
        return sftp_server_version(this._sftpSession);
    }

    string canonicalizePath(string path) {
        auto result = sftp_canonicalize_path(this._sftpSession, toStrZ(path));
        if (result is null) {
            throw new SFTPException(SFTPError.Unknown, this._session._session);
        }
        scope(exit) ssh_string_free_char(result);
        return copyFromStrZ(result);
    }

    bool isExtensionSupported(string name, string data) {
        return sftp_extension_supported(this._sftpSession, toStrZ(name), toStrZ(data)) == 0 ? 
            false : true;
    }

    string getExtensionData(uint index) {
        return fromStrZ(sftp_extensions_get_data(this._sftpSession, index));
    }

    string getExtensionName(uint index) {
        return fromStrZ(sftp_extensions_get_name(this._sftpSession, index));
    }


    // TODO: accessType to flags
    // TODO: mode consts
    SFTPFile open(string file, int accessType, uint mode) {
        auto result = sftp_open(this._sftpSession, toStrZ(file), accessType, cast(mode_t) mode);
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
        return new SFTPFile(this, result);
    }

    SFTPDirectory openDir(string path) {
        auto result = sftp_opendir(this._sftpSession, toStrZ(path));
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
        return new SFTPDirectory(this, result);
    }

    void chmod(string file, uint mode) {
        auto rc = sftp_chmod(this._sftpSession, toStrZ(file), cast(mode_t) mode);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    void chown(string file, uint uid, uint gid) {
        auto rc = sftp_chown(this._sftpSession, toStrZ(file), cast(uid_t) uid, cast(gid_t) gid);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    void mkdir(string dir, uint mode) {
        auto rc = sftp_mkdir(this._sftpSession, toStrZ(dir), cast(mode_t) mode);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    string readlink(string path) {
        auto result = sftp_readlink(this._sftpSession, toStrZ(path));
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
        scope(exit) ssh_string_free_char(result);
        return copyFromStrZ(result);
    }

    void symlink(string target, string dest) {
        auto rc = sftp_symlink(this._sftpSession, toStrZ(target), toStrZ(dest));
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    void rename(string original, string newName) {
        auto rc = sftp_rename(this._sftpSession, toStrZ(original), toStrZ(newName));
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    void unlink(string path) {
        auto rc = sftp_unlink(this._sftpSession, toStrZ(path));
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    void rmdir(string path) {
        auto rc = sftp_rmdir(this._sftpSession, toStrZ(path));
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    void stat(string path, out SFTPAttributes attrs) {
        auto result = sftp_stat(this._sftpSession, toStrZ(path));
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
        convertAndFreeSftpAttributes(result, attrs);
    }

    void lstat(string path, out SFTPAttributes attrs) {
        auto result = sftp_lstat(this._sftpSession, toStrZ(path));
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
        convertAndFreeSftpAttributes(result, attrs);
    }

    void setStat(string path, SFTPAttributes attrs) {
        sftp_attributes_struct attrsStruct;
        convertAndSetSftpAttributes(&attrsStruct, attrs);
        scope(exit) {
            if (attrsStruct.extended_data !is null) {
                ssh_string_free(attrsStruct.extended_data);
            }
            if (attrsStruct.extended_type !is null) {
                ssh_string_free(attrsStruct.extended_type);
            }
        }
        auto rc = sftp_setstat(this._sftpSession, toStrZ(path), &attrsStruct);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
    }

    SFTPStatVFS statVFS(string path) {
        auto result = sftp_statvfs(this._sftpSession, toStrZ(path));
        if (result is null) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }
        scope(exit) sftp_statvfs_free(result);
        
        SFTPStatVFS resultObj;
        memcpy(&resultObj, result, SFTPStatVFS.sizeof);
        return resultObj;
    }

    TimesValue utimes(string file) {
        timeval result;
        auto rc = sftp_utimes(this._sftpSession, toStrZ(file), &result);
        if (rc != SSH_OK) {
            throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
        }

        TimesValue resulObj = {
            sec: result.tv_sec,
            usec: result.tv_usec
        };
        return resulObj;
    }


    version (LIBSSH_WITH_SERVER) {
        void serverInit() {
            auto rc = sftp_server_init(this._sftpSession);
            if (rc != SSH_OK) {
                throw new SFTPException(sftp_get_error(this._sftpSession), this._session._session);
            }
        }
    }


    ~this() {
        this._dispose(true);
    }
    
    override void dispose() {
        this._dispose(false);
    }
    
    package {
        this(SSHSession parent, sftp_session sftpSession) {
            this._session = parent;
            this._sftpSession = sftpSession;
        }
    }
    
    private {
        void _dispose(bool fromDtor) {
            if (this._sftpSession !is null) {
                sftp_free(this._sftpSession);
                this._session = null;
                this._sftpSession = null;
            }
        }
        
        SSHSession _session;
        sftp_session _sftpSession;
    }
}

private {
    string convertSSHStringToString(ssh_string s) {
        auto dataPtr = ssh_string_data(s);
        if (dataPtr is null) {
            return null;
        }

        auto len = ssh_string_len(s);
        auto result = new char[len];
        memcpy(result.ptr, dataPtr, len);
        return cast(string) result;
    }

    ssh_string convertStringToSSHString(string s) {
        auto result = ssh_string_new(s.length);
        if (result is null) {
            return null;
        }
        if (ssh_string_fill(result, s.ptr, s.length) < 0) {
            ssh_string_free(result);
            return null;
        }
        return null;
    }

    void convertAndFreeSftpAttributes(sftp_attributes attrs, out SFTPAttributes outAttrs) {
        scope(exit) sftp_attributes_free(attrs);

        outAttrs.name = copyFromStrZ(attrs.name);
        outAttrs.longName = copyFromStrZ(attrs.longname);
        outAttrs.flags = attrs.flags;
        outAttrs.type = attrs.type;
        outAttrs.size = attrs.size;
        outAttrs.uid = attrs.uid;
        outAttrs.gid = attrs.gid;
        outAttrs.owner = copyFromStrZ(attrs.owner);
        outAttrs.group = copyFromStrZ(attrs.group);
        outAttrs.permissions = attrs.permissions;
        outAttrs.atime64 = attrs.atime64;
        outAttrs.atime = attrs.atime;
        outAttrs.atimeNSeconds = attrs.atime_nseconds;
        outAttrs.createtime = attrs.createtime;
        outAttrs.createtimeNSeconds = attrs.createtime_nseconds;
        outAttrs.mtime64 = attrs.mtime64;
        outAttrs.mtime = attrs.mtime;
        outAttrs.mtimeNSeconds = attrs.mtime_nseconds;
        outAttrs.acl = convertSSHStringToString(attrs.acl);
        outAttrs.extendedCount = attrs.extended_count;
        outAttrs.extendedType = convertSSHStringToString(attrs.extended_type);
        outAttrs.extendedData = convertSSHStringToString(attrs.extended_data);
    }

    void convertAndSetSftpAttributes(sftp_attributes outAttrs, SFTPAttributes attrs) {        
        outAttrs.name = copyToStrZ(attrs.name);
        outAttrs.longname = copyToStrZ(attrs.longName);
        outAttrs.flags = attrs.flags;
        outAttrs.type = attrs.type;
        outAttrs.size = attrs.size;
        outAttrs.uid = attrs.uid;
        outAttrs.gid = attrs.gid;
        outAttrs.owner = copyToStrZ(attrs.owner);
        outAttrs.group = copyToStrZ(attrs.group);
        outAttrs.permissions = attrs.permissions;
        outAttrs.atime64 = attrs.atime64;
        outAttrs.atime = attrs.atime;
        outAttrs.atime_nseconds = attrs.atimeNSeconds;
        outAttrs.createtime = attrs.createtime;
        outAttrs.createtime_nseconds = attrs.createtimeNSeconds;
        outAttrs.mtime64 = attrs.mtime64;
        outAttrs.mtime = attrs.mtime;
        outAttrs.mtime_nseconds = attrs.mtimeNSeconds;
        outAttrs.acl = convertStringToSSHString(attrs.acl);
        outAttrs.extended_count = attrs.extendedCount;
        outAttrs.extended_type = convertStringToSSHString(attrs.extendedType);
        outAttrs.extended_data = convertStringToSSHString(attrs.extendedData);
    }
}
