import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreJKS {

    //BURASI YAZILACAK
    public static String createKeyStoreFile(String jksFileName) throws IOException, InterruptedException {
        Process process = new ProcessBuilder("bash", "-c", "keytool -genkey -alias server -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -storetype JKS -keystore server.keystore.jks "
                + "-storepass mypwdr -keypass mypwdr -dname	"
                + "\"CN=my.server.com, OU=EastCoast, O=MyComp Ltd, L=New York, ST=, C=US\" "
                + "-ext \"SAN=dns:my.server.com,dns:www.my.server.com,ip:11.22.33.44\" "
                + "-validity 7200").redirectErrorStream(true).start();
        process.waitFor();
        return "mypwdr";
    }

    public static boolean isAlive(Process p) {
        try {
            p.exitValue();
            return false;
        }
        catch (IllegalThreadStateException e) {
            return true;
        }
    }




    public static void createSelfSignedCertificateFile(String jskFileName,String certificateFileName) throws IOException {
        try {
            Process exec = Runtime.getRuntime().exec("keytool -export -alias server -keystore " + jskFileName + " -rfc -file " + certificateFileName);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static KeyStore getKeyStore(String jskFileName,String keyStorePassword){
        KeyStore jks = null;
        try {
            jks = KeyStore.getInstance("JKS");
            jks.load(new FileInputStream(jskFileName),keyStorePassword.toCharArray());
            return jks;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }
    public static Key getPrivateKeyFromKeyStore(String jksFileName,String alias,String keyStorePassword) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        return getKeyStore(jksFileName,keyStorePassword).getKey(alias,keyStorePassword.toCharArray());
    }
}
