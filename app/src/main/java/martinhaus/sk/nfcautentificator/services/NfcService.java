package martinhaus.sk.nfcautentificator.services;

import android.nfc.cardemulation.HostApduService;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
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
    String n;
    String g;
    String alice_sends;
    long bob_secret = 15;
    String aesKey;
    String sample_key = "24e042f7-5e43-4543-a614-4bdca32ee7c2";
    String bob_computes;
    @Override
    public void onDeactivated(int reason) { }


    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {

        // Extract header and body of recieved APDU command into dedicated object
        ApduMessage apduMessage = ApduUtils.extractAPDUDataAndHeader(commandApdu);

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SELECT_APDU_HEADER), apduMessage.getHeader())) {
            return SELECT_OK_SW;
        }

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.REQUEST_PUBLIC_KEY), apduMessage.getHeader())) {
            Log.i(TAG, "Request for PK creation");
            String pkey = "";
            try {
                kp = RsaUtils.generateRSAKeys();
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
                pkey =  new String(Base64.encode(x509EncodedKeySpec.getEncoded(), Base64.NO_WRAP), "UTF-8");
            } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            Log.i(TAG, "PK  " + kp.getPrivate());
            return ApduUtils.ConcatArrays((pkey.getBytes()), SELECT_OK_SW);
        }

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

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.REQUEST_OTP), apduMessage.getHeader())) {
            String encrypted = "";
            try {
                encrypted = AesUtils.encrypt(aesKey, sample_key);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
            System.out.println("AES encrypted " + encrypted);
            return ApduUtils.ConcatArrays(encrypted.getBytes(StandardCharsets.UTF_8), SELECT_OK_SW);

        }

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.REQUEST_OTP_DH), apduMessage.getHeader())) {
            String encrypted = "";
            try {
                encrypted = AesUtils.encrypt(aesKey, sample_key);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (GeneralSecurityException e) {
                e.printStackTrace();
            }
            System.out.println("AES encrypted " + encrypted);
            return ApduUtils.ConcatArrays(encrypted.getBytes(StandardCharsets.UTF_8), SELECT_OK_SW);

        }

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_DH_N), apduMessage.getHeader())) {

            n = ByteArrayToAsciiString(apduMessage.getBody());
            System.out.println("N:" + n);

        }
        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_DH_G), apduMessage.getHeader())) {

            g = ByteArrayToAsciiString(apduMessage.getBody());
            System.out.println("G: " + g);
        }

        if (Arrays.equals(HexStringToByteArray(ApduMessageHeader.SEND_DH_ALICE), apduMessage.getHeader())) {

            alice_sends = ByteArrayToAsciiString(apduMessage.getBody());

            System.out.println("ALICE SENDS: " + alice_sends);
            long bob_sends = (long) (Math.floor(Math.pow(Long.valueOf(g), bob_secret)) % Long.valueOf(n));
            bob_computes = String.valueOf((long) Math.floor(Math.pow(Long.valueOf(alice_sends), bob_secret) % Long.valueOf(n)));


            System.out.println("BOB SENDS: " + bob_sends);
            System.out.println("BOB COMPUTES: " + bob_computes);
            aesKey = bob_computes;



            return ApduUtils.ConcatArrays(HexStringToByteArray(ApduUtils.toHex(String.valueOf(bob_sends))), SELECT_OK_SW);
        }


        else {
            Log.i(TAG, "Received message: " + ApduUtils.ByteArrayToAsciiString(commandApdu));
            return ApduUtils.ConcatArrays(HexStringToByteArray("FFFF"), SELECT_OK_SW);
        }
//        return UNKNOWN_CMD_SW;
    }


}
