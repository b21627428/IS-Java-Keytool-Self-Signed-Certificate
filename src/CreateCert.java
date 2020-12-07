import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.security.Key;
import java.util.Base64;


public abstract class CreateCert {

    public static void work (String[] args) throws Exception {

        String publicKeyCertificateFile = args[4];
        String privateKeyFile = args[2];
        String thisIsPrivateKeyString = "This is private key\n";

        //KEYSTORE CREATING FROM BASH
        String keyStorePassword = KeyStoreJKS.createKeyStoreFile("server.keystore.jks");
//        String keyStorePassword = "mypwdr";

        //CERTIFICATE WRITE TO PUBLIC KEY CERTIFICATE FILE
        KeyStoreJKS.createSelfSignedCertificateFile("server.keystore.jks",publicKeyCertificateFile);

        //PRIVATE KEY GETTING FROM KEYSTORE
        Key privateKeyFromKeyStore = KeyStoreJKS.getPrivateKeyFromKeyStore("server.keystore.jks","server", keyStorePassword);

        BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(privateKeyFile));
        bufferedWriter.write(thisIsPrivateKeyString);
        String encoded = Base64.getEncoder().encodeToString(privateKeyFromKeyStore.getEncoded());
        bufferedWriter.write(encoded);
        bufferedWriter.close();


        String str = thisIsPrivateKeyString + encoded;
        //KEYSTORE PASSWORD HASHING WITH MD5  , PRIVATE KEY AES ENCRYPTION , KEY = HASH DIGEST
        byte[] md5Digest = Hash.getDigest("MD5", keyStorePassword);
        String encryptedPrivateKeyByMD5withPassword = EncryptionDecryption.encrypt(str, "AES", new SecretKeySpec(md5Digest, "AES"));
        File.write(args[2],encryptedPrivateKeyByMD5withPassword);

    }
}
