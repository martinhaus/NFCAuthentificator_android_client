package martinhaus.sk.nfcautentificator.common;

import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import static org.junit.Assert.*;

public class RsaUtilsTest {

    @Test
    public void generateRSAKeys() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        String message = "Hello RSA test";

        KeyPair kp = RsaUtils.generateRSAKeys();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        Cipher cipher2 = Cipher.getInstance("RSA");
        cipher2.init(Cipher.DECRYPT_MODE, kp.getPrivate());
        byte[] decryptedBytes = cipher2.doFinal(encryptedBytes);

        assertArrayEquals(message.getBytes(), decryptedBytes);
    }
}