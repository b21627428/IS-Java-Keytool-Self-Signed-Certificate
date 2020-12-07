import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

public abstract class CreateReg {

    public static void work(String[] args){

        BufferedWriter logFileWriter = null;
        String thisIsPrivateKeyString = "This is private key\n";
        try {
            String logFilePath = args[6];
            String privateKeyFilePath = args[10];
            String registerFilePath = args[2];
            String filesWhichWillBeHashedOnThatPath = args[4];
            String hashMethod = args[8];

            logFileWriter = new BufferedWriter(new FileWriter(logFilePath,true));

            //PRIVATE KEY GETTING
            String decryptedPrivateKey = decryptPrivateKey(privateKeyFilePath);
            //OPENING REGISTER FILE AND LOGGING
            BufferedWriter registerFileWriter = new BufferedWriter(new FileWriter((registerFilePath)));
            logFileWriter.write(getCurrentTimeStamp()+" Registry file is created at "+registerFilePath+"\n" );

            //OPENING FILES ON PATH AND WRITING HASH VALUES OF FILE TO REGISTER FILE AND LOGGING
            fillRegisterFileContent(filesWhichWillBeHashedOnThatPath,hashMethod,registerFileWriter,logFileWriter);

            //REGISTER FILE GETTING ALL CONTENT AND HASHING
            String registerFileAllContent = File.read2(registerFilePath);
            byte[] registerFileAllContentDigest = Hash.getDigest(hashMethod, registerFileAllContent);


            byte[] signature = sign(hashMethod, decryptedPrivateKey.split("\n")[1], registerFileAllContentDigest);

            //SIGNING
            registerFileWriter.write(Base64.getEncoder().encodeToString(signature));
            registerFileWriter.close();

        } catch (BadPaddingException e){ //WRONG PASSWORD LOGGING AND TERMINATE APP
            try {
                logFileWriter.write(getCurrentTimeStamp()+" Wrong password attempt'\n");
                logFileWriter.close();
                System.exit(1);
            }catch (Exception e2){
                e2.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            logFileWriter.close();
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static void fillRegisterFileContent(String filesWhichWillBeHashedOnThatPath,String hashMethod,BufferedWriter registerFileWriter,BufferedWriter logFileWriter) throws IOException {
        Stream<Path> walk = Files.walk(Paths.get(filesWhichWillBeHashedOnThatPath));
        AtomicInteger fileCounter = new AtomicInteger();
        walk.filter(Files::isRegularFile)
                .forEach(
                        file -> {
                            String fileName = file.toString();
                            String content = File.read(fileName);
                            byte[] digest = Hash.getDigest(hashMethod, content);
                            try {
                                registerFileWriter.write(fileName+" "+Base64.getEncoder().encodeToString(digest)+"\n");
                                registerFileWriter.flush();
                                fileCounter.getAndIncrement();
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        }
                );
        logFileWriter.write(getCurrentTimeStamp()+": "+fileCounter.get()+" files are added to the registry creation is finished!\n");
    }

    private static String decryptPrivateKey(String privateKeyFilePath) throws Exception {
        //PRIVATE KEY READING AND DECRYPT WITH HASH VALUE
        byte[] md5PasswordDigest = getHashedPasswordFromConsole();
        String privateKeyFromPrivateKeyFile = File.read(privateKeyFilePath);
        return EncryptionDecryption.decrypt(privateKeyFromPrivateKeyFile, "AES", new SecretKeySpec(md5PasswordDigest, "AES"));
    }

    private static byte[] sign(String hashMethod,String decryptedPrivateKey,byte[] registerFileAllContentDigest) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, UnrecoverableKeyException, KeyStoreException, InvalidKeySpecException {
        // GETTING PRIVATE KEY FROM STRING AND SIGNING AND WRITING TO REGISTER FILE
        Signature sig = Signature.getInstance((hashMethod.equals("SHA-256") ? "SHA256" : "MD5") + "withRSA");
        sig.initSign(KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode((decryptedPrivateKey.getBytes())))));
        sig.update(registerFileAllContentDigest);
        return sig.sign();
    }

    private static byte[] getHashedPasswordFromConsole(){
        //PASSWORD FROM CONSOLE HASHING MD5
        System.out.print("Enter password: ");
        Scanner scanner = new Scanner(System.in);
        String passwordFromConsole = scanner.nextLine();
        return Hash.getDigest("MD5", passwordFromConsole);
    }

    private static String getCurrentTimeStamp(){
        return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Timestamp(System.currentTimeMillis()));
    }
}
