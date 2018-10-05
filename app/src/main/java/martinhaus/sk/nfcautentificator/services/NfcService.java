package martinhaus.sk.nfcautentificator.services;

import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import martinhaus.sk.nfcautentificator.common.ApduUtils;
import martinhaus.sk.nfcautentificator.common.RsaUtils;
import martinhaus.sk.nfcautentificator.model.ApduMessage;
import martinhaus.sk.nfcautentificator.model.ApduMessageHeader;

import static martinhaus.sk.nfcautentificator.model.ApduResponseStatusWord.SELECT_OK_SW;
import static martinhaus.sk.nfcautentificator.model.ApduResponseStatusWord.UNKNOWN_CMD_SW;

public class NfcService extends HostApduService {

    private static final String TAG = "CardService";
    KeyPair kp;

    @Override
    public void onDeactivated(int reason) { }


    @Override
    public byte[] processCommandApdu(byte[] commandApdu, Bundle extras) {
        Log.i(TAG, "Received APDU: " + ApduUtils.ByteArrayToHexString(commandApdu));

        ApduMessage apduMessage = ApduUtils.extractAPDUDataAndHeader(commandApdu);

        if (Arrays.equals(ApduUtils.HexStringToByteArray(ApduMessageHeader.REQUEST_PUBLIC_KEY), apduMessage.getHeader())) {
            Log.i(TAG, "Request for PK creation");
            String pkey = "";
            try {
                kp = RsaUtils.generateRSAKeys();
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());
                pkey =  new String(Base64.encode(x509EncodedKeySpec.getEncoded(), Base64.NO_WRAP), "UTF-8");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            Log.i(TAG, "PK  " + pkey);
            return ApduUtils.ConcatArrays((pkey.getBytes()), SELECT_OK_SW);
        }

        if (Arrays.equals(ApduUtils.HexStringToByteArray(ApduMessageHeader.SEND_AES_KEY), apduMessage.getHeader())) {
//            byte [] encodedMessage = HexStringToByteArray(new String(apduMessage.getBody()));

            byte[] data = Base64.decode(apduMessage.getBody(), Base64.DEFAULT);
            System.out.println(ApduUtils.ByteArrayToAsciiString(data));
            try {
                Cipher cipher1 = Cipher.getInstance("RSA");
                cipher1.init(Cipher.DECRYPT_MODE, kp.getPrivate());
                byte[] decryptedBytes = cipher1.doFinal(data);
                String decrypted = new String(decryptedBytes);
                Log.i(TAG, "Encoded message: " + decrypted);

            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            }
            System.out.println();

        }

        else {
            Log.i(TAG, "Received message: " + ApduUtils.ByteArrayToAsciiString(commandApdu));
            return ApduUtils.ConcatArrays(ApduUtils.HexStringToByteArray("FFFF"), SELECT_OK_SW);
        }
        return UNKNOWN_CMD_SW;
    }


}
