package controls;

import java.security.MessageDigest;

/**
 * Broken hash used to store a password. OWASP Benchmark categories "hash" and
 * "crypto".
 *
 * MD5 here is a bare digest with no salt and no work factor; the correct
 * construction is a password KDF (bcrypt/scrypt/argon2/PBKDF2).
 */
public class ctrl_hash_md5_password {

    public byte[] hash(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(password.getBytes("UTF-8"));
    }
}
