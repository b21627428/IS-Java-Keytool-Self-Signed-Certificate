import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {

    public static byte[] getDigest(String hashMethod,String content){
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(hashMethod);
            md.update(content.getBytes());
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }
}
