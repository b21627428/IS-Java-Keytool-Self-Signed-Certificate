import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;


public class KeyStoreJKS {


    public static void createKeyStoreFile() throws IOException, InterruptedException {

        Process process = new ProcessBuilder("bash", "-c", "keytool -genkey -alias server -keyalg RSA -keysize 2048 -sigalg SHA256withRSA -storetype JKS -keystore server.keystore.jks "
                + "-storepass mypwdr -keypass mypwdr -dname	\"CN=, OU=, O=, L=, ST=, C=\" -validity 7200").redirectErrorStream(true).start();
        process.waitFor();
    }


    public static void createSelfSignedCertificateFile(String certificateFileName)  {
        try {
            Runtime.getRuntime().exec("keytool -export -alias server -keystore server.keystore.jks -rfc -file " + certificateFileName);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static Key getPrivateKeyFromKeyStore() throws UnrecoverableKeyException{
        KeyStore jks = null;
        try {
            jks = KeyStore.getInstance("JKS");
            jks.load(new FileInputStream("server.keystore.jks"),"mypwdr".toCharArray());
            return jks.getKey("server","mypwdr".toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }
        return null;
    }
}
