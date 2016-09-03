module libssh.key;

import core.stdc.string : memcpy;

import libssh.c_bindings.libssh;
import libssh.errors;
import libssh.utils;

enum PublicKeyHashType : int {
    SHA1 = ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_SHA1,
    MD5 = ssh_publickey_hash_type.SSH_PUBLICKEY_HASH_MD5,
}

enum KeyComparePart : ssh_keycmp_e {
    Public = ssh_keycmp_e.SSH_KEY_CMP_PUBLIC,
    Private = ssh_keycmp_e.SSH_KEY_CMP_PRIVATE,
}

enum KeyType : ssh_keytypes_e {
    Unknown = ssh_keytypes_e.SSH_KEYTYPE_UNKNOWN,
    DSS = ssh_keytypes_e.SSH_KEYTYPE_DSS,
    RSA = ssh_keytypes_e.SSH_KEYTYPE_RSA,
    RSA1 = ssh_keytypes_e.SSH_KEYTYPE_RSA1,
    ECDSA = ssh_keytypes_e.SSH_KEYTYPE_ECDSA,
    ED25519 = ssh_keytypes_e.SSH_KEYTYPE_ED25519,
}

enum PublicKeyState : int {
    Error = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_ERROR,
    None = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_NONE,
    Valid = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_VALID,
    Wrong = ssh_publickey_state_e.SSH_PUBLICKEY_STATE_WRONG,
}

class SSHKey : Disposable {
    alias AuthCallback = string delegate(string prompt, bool echo, bool verify);

    @property bool isPrivate() {
        return ssh_key_is_private(this._key) == 0 ? false : true;
    }

    @property bool isPublic() {
        return ssh_key_is_public(this._key) == 0 ? false : true;
    }

    @property KeyType keyType() {
        return cast(KeyType) ssh_key_type(this._key);
    }

    @property string ecdsaName() {
        return fromStrZ(ssh_pki_key_ecdsa_name(this._key));
    }

    ubyte[] getHash(PublicKeyHashType hashType) {
        ubyte* hash;
        size_t hashLength;
        auto rc = ssh_get_publickey_hash(this._key, cast(ssh_publickey_hash_type) hashType, &hash, &hashLength);
        checkForRCError(rc, rc);
        scope(exit) ssh_clean_pubkey_hash(&hash);
        
        ubyte[] result = new ubyte[hashLength];
        memcpy(result.ptr, hash, hashLength);
        return result;
    }

    void exportPrivateKeyToFile(string passPhrase, string fileName, AuthCallback authFn = null) {
        auto rc = ssh_pki_export_privkey_file(this._key, toStrZ(passPhrase),
            authFn is null ? null : &nativeAuthCallback, authFn.ptr, toStrZ(fileName));
        checkForRCError(rc, rc);
    }

    SSHKey exportPrivateKeyToPublicKey() {
        ssh_key result;
        auto rc = ssh_pki_export_privkey_to_pubkey(this._key, &result);
        checkForRCError(rc, rc);
        checkForNullError(result, rc);
        return new SSHKey(result);
    }

    string exportPrivateKeyToBase64() {
        char* result;
        auto rc = ssh_pki_export_pubkey_base64(this._key, &result);
        checkForNullError(result, rc);
        scope(exit) ssh_string_free_char(result);
        checkForRCError(rc, rc);
        return copyFromStrZ(result);
    }

    override bool opEquals(Object o) {
        auto b = cast(SSHKey) o;
        if (b is null) {
            return false;
        }
        return isKeysEqual(this, b, KeyComparePart.Private) &&
            isKeysEqual(this, b, KeyComparePart.Public);
    }

    static bool isKeysEqual(const SSHKey a, const SSHKey b, KeyComparePart comparePart) {
        return ssh_key_cmp(a._key, b._key, comparePart) == 0 ? true : false;
    }

    static KeyType keyTypeFromString(string name) {
        return cast(KeyType) ssh_key_type_from_name(toStrZ(name));
    }

    static string keyTypeToString(KeyType kt) {
        return copyFromStrZ(ssh_key_type_to_char(kt));
    }

    static SSHKey importPrivateKeyFromBase64(string b64, string passPhrase,
            AuthCallback authFn = null) {
        ssh_key result;
        auto rc = ssh_pki_import_privkey_base64(toStrZ(b64), toStrZ(passPhrase),
            authFn is null ? null : &nativeAuthCallback, authFn.ptr, &result);
        checkForRCError(rc, rc);
        checkForNullError(result, rc);
        return new SSHKey(result);
    }

    static SSHKey importPrivateKeyFromFile(string fileName, string passPhrase,
        AuthCallback authFn = null) {
        ssh_key result;
        auto rc = ssh_pki_import_privkey_file(toStrZ(fileName), toStrZ(passPhrase),
            authFn is null ? null : &nativeAuthCallback, authFn.ptr, &result);
        checkForRCError(rc, rc);
        checkForNullError(result, rc);
        return new SSHKey(result);
    }

    static SSHKey importPublicKeyFromBase64(string b64, KeyType keyType) {
        ssh_key result;
        auto rc = ssh_pki_import_pubkey_base64(toStrZ(b64), cast(ssh_keytypes_e) keyType,
            &result);
        checkForRCError(rc, rc);
        checkForNullError(result, rc);
        return new SSHKey(result);
    }

    static SSHKey importPublicKeyFromFile(string fileName) {
        ssh_key result;
        auto rc = ssh_pki_import_pubkey_file(toStrZ(fileName), &result);
        checkForRCError(rc, rc);
        checkForNullError(result, rc);
        return new SSHKey(result);
    }

    static SSHKey generate(KeyType keyType, int bitsLength) {
        ssh_key result;
        auto rc = ssh_pki_generate(cast(ssh_keytypes_e) keyType, bitsLength, &result);
        checkForRCError(rc, rc);
        checkForNullError(result, rc);
        return new SSHKey(result);
    }

    override void dispose() {
        this._dispose(false);
    }

    this() {
        auto key = ssh_key_new();
        checkForNullError(key, "Error while creating ssh key");
        this(key);
    }
    
    ~this() {
        this._dispose(true);
    }
    
    package {
        this(ssh_key key) {
            this._key = key;
        }
        
        ssh_key _key;
    }
    
    private {
        void _dispose(bool fromDtor) {
            if (this._key !is null) {
                ssh_key_free(this._key);
                this._key = null;
            }
        }
    }
}


private {
    extern(C) int nativeAuthCallback(const char *prompt, char *buf, size_t len,
            int echo, int verify, void *userdata) {
        auto cb = cast(SSHKey.AuthCallback*) userdata;
        
        if (cb is null) {
            return SSH_ERROR;
        }
        
        try {
            auto result = (*cb)(fromStrZ(prompt), echo == 0 ? false : true, 
                verify == 0 ? false : true);
            if (result is null) {
                return SSH_ERROR;
            }
            
            if (len < result.length + 1) {
                return SSH_ERROR;
            }
            
            import core.stdc.string : memcpy;
            memcpy(buf, result.ptr, result.length);
            buf[result.length] = 0;
            
            return SSH_OK;
        } catch (Exception) {
            return SSH_ERROR;
        }
    }
}
