package martinhaus.sk.nfcautentificator.model;

public interface ApduCommand {
    byte[] process(ApduMessage apduMessage);
}
