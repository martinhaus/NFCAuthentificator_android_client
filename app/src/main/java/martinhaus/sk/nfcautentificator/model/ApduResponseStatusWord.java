package martinhaus.sk.nfcautentificator.model;

import static martinhaus.sk.nfcautentificator.common.ApduUtils.HexStringToByteArray;

public class ApduResponseStatusWord {
    public static final byte[] SELECT_OK_SW = HexStringToByteArray("9000");
    public static final byte[] UNKNOWN_CMD_SW = HexStringToByteArray("0000");
}
