package martinhaus.sk.nfcautentificator.common;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesUtils {

    private static byte[] ivBytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    public static SecretKeySpec generateKey(String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = password.getBytes("UTF-8");
        digest.update(bytes, 0, bytes.length);
        byte[] key = digest.digest();

        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        return secretKeySpec;
    }

    public static String encrypt(final String password, String message) throws UnsupportedEncodingException, GeneralSecurityException {
        SecretKeySpec secretKeySpec = generateKey(password);


        SecureRandom random = new SecureRandom();
//        ivBytes = random.generateSeed(16);

        byte[] cipherText = encrypt(secretKeySpec, ivBytes, message.getBytes("UTF-8"));
        return  Base64.encodeToString(cipherText, Base64.NO_WRAP);
    }

    public static byte[] encrypt(final SecretKeySpec key, final byte[] iv, final byte[] message) throws GeneralSecurityException {
        final Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(message);
    }

}
