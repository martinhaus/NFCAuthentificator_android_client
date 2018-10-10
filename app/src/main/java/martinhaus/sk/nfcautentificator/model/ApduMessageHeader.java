package martinhaus.sk.nfcautentificator.model;

public class ApduMessageHeader {
    public static final String SELECT_APDU_HEADER = "00A40400";
    public static final String REQUEST_PUBLIC_KEY = "00030400";
    public static final String SEND_AES_KEY = "00040400";
    public static final String SEND_DH_N = "00110400";
    public static final String SEND_DH_G = "00120400";
    public static final String SEND_DH_ALICE = "00130400";
    public static final String REQUEST_DH_BOB = "00140400";
    public static final String REQUEST_OTP = "00041000";
    public static final String REQUEST_OTP_DH = "00042000";
}
