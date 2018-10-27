package martinhaus.sk.nfcautentificator.services;

import android.nfc.cardemulation.HostApduService;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import martinhaus.sk.nfcautentificator.common.AesUtils;
import martinhaus.sk.nfcautentificator.common.ApduUtils;
import martinhaus.sk.nfcautentificator.common.RsaUtils;
import martinhaus.sk.nfcautentificator.model.ApduMessage;
import martinhaus.sk.nfcautentificator.model.ApduMessageHeader;

import static martinhaus.sk.nfcautentificator.common.ApduUtils.ByteArrayToAsciiString;
import static martinhaus.sk.nfcautentificator.common.ApduUtils.ByteArrayToHexString;
import static martinhaus.sk.nfcautentificator.common.ApduUtils.HexStringToByteArray;
import static martinhaus.sk.nfcautentificator.model.ApduResponseStatusWord.SELECT_OK_SW;
import static martinhaus.sk.nfcautentificator.model.ApduResponseStatusWord.UNKNOWN_CMD_SW;

public class NfcService extends HostApduService {

    private static final String TAG = "NfcAuthService";
    KeyPair kp;
    BigInteger n;
    BigInteger g;
    BigInteger alice_sends;
    BigInteger bob_secret = new BigInteger("15");
    String aesKey;
    String sample_key = "24e042f7-5e43-4543-a614-4bdca32ee7c2";
    String bob_computes;
    @Override
    public void onDeactivated(int reason) { }


    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {

        // Extract header and body of recieved APDU command into dedicated object
        ApduMessage apduMessage = ApduUtils.extractAPDUDataAndHeader(commandApdu);

        // Initial connection message
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SELECT_APDU_HEADER), apduMessage.getHeader())) {
            return SELECT_OK_SW;
        }

        // Request for sending public key from this device
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.REQUEST_PUBLIC_KEY), apduMessage.getHeader())) {
            String pkey = "";
            try {
                kp = RsaUtils.generateRSAKeys();
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
                pkey =  new String(Base64.encode(x509EncodedKeySpec.getEncoded(), Base64.NO_WRAP), "UTF-8");
            } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            return ApduUtils.ConcatArrays((pkey.getBytes()), SELECT_OK_SW);
        }

        // Receive AES key from the reader
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_AES_KEY), apduMessage.getHeader())) {

            byte[] decodedMessage = Base64.decode(apduMessage.getBody(), Base64.DEFAULT);

            try {
                Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher1.init(Cipher.DECRYPT_MODE, kp.getPrivate());
                byte[] decryptedBytes = cipher1.doFinal(decodedMessage);
                aesKey = new String(decryptedBytes);
            } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }

        // Request for OTP
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.REQUEST_OTP), apduMessage.getHeader())) {
            String encrypted = "";
            try {
                encrypted = AesUtils.encrypt(aesKey, sample_key);
            } catch (UnsupportedEncodingException | GeneralSecurityException e) {
                e.printStackTrace();
            }
            return ApduUtils.ConcatArrays(encrypted.getBytes(StandardCharsets.UTF_8), SELECT_OK_SW);

        }

        // Receive prime and primitive root modulo from the reader to be used in DH key exchange
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_DH_N), apduMessage.getHeader())) {
            n = new BigInteger(ByteArrayToAsciiString(apduMessage.getBody()));
        }
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_DH_G), apduMessage.getHeader())) {
            g = new BigInteger(ByteArrayToAsciiString(apduMessage.getBody()));
        }

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_DH_ALICE), apduMessage.getHeader())) {

            alice_sends = new BigInteger(ByteArrayToAsciiString(apduMessage.getBody()));

            BigInteger bob_sends = g.modPow(bob_secret, n);
            bob_computes = String.valueOf(alice_sends.modPow(bob_secret, n));

            aesKey = bob_computes;

            return ApduUtils.ConcatArrays(HexStringToByteArray(ApduUtils.toHex(String.valueOf(bob_sends))), SELECT_OK_SW);
        }

        // Command not recognized
        else {
            return ApduUtils.ConcatArrays(HexStringToByteArray(""), UNKNOWN_CMD_SW);
        }
    }


}
