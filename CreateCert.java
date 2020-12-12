import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Scanner;


public abstract class CreateCert {

    public static void work (String[] args) throws Exception {

        String publicKeyCertificateFile = args[4];
        String privateKeyFile = args[2];

        //KEYSTORE CREATING FROM BASH
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter password (for AES KEY while encryption of private key ) : ");
        String password = scanner.nextLine();

        KeyStoreJKS.createKeyStoreFile();
        //CERTIFICATE WRITE TO PUBLIC KEY CERTIFICATE FILE
        KeyStoreJKS.createSelfSignedCertificateFile(publicKeyCertificateFile);

        //PRIVATE KEY GETTING FROM KEYSTORE AND ADDING DUMMY DATA
        Key privateKeyFromKeyStore = KeyStoreJKS.getPrivateKeyFromKeyStore();
        String thisIsPrivateKeyString = "This is private key\n";
        String encoded = Base64.getEncoder().encodeToString(privateKeyFromKeyStore.getEncoded());
        String str = thisIsPrivateKeyString + encoded;

        //PASSWORD HASHING FOR AES KEY
        byte[] aesKey = Hash.getDigest("MD5", password);

        //AES ENCRYPTION
        String encryptedPrivateKeyByMD5withPassword = EncryptionDecryption.encrypt(str, "AES", new SecretKeySpec(aesKey, "AES"));

        //WRITING TO PRIVATE KEY FILE
        File.write(privateKeyFile,encryptedPrivateKeyByMD5withPassword);

    }
}
