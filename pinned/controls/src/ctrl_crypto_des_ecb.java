package controls;

import javax.crypto.Cipher;

/**
 * Broken cipher with a broken mode of operation. OWASP Benchmark category
 * "crypto".
 *
 * DES has a 56-bit key, and ECB leaks structure by encrypting identical blocks
 * identically. AES-GCM is the modern default.
 */
public class ctrl_crypto_des_ecb {

    public byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "DES"));
        return c.doFinal(data);
    }
}
