package martinhaus.sk.nfcautentificator.model;

public class ApduMessage {
    private byte[] header;
    private byte[] body;

    public ApduMessage(byte[] header, byte[] body) {
        this.header = header;
        this.body = body;
    }

    public byte[] getHeader() {
        return header;
    }

    public void setHeader(byte[] header) {
        this.header = header;
    }

    public byte[] getBody() {
        return body;
    }

    public void setBody(byte[] body) {
        this.body = body;
    }
}
