import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Integrity {

    public static void work(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, CertificateException {

        String registerFilePath = args[2];
        String hashMethod = args[8];
        String publicCertificatePath = args[10];
        String logFilePath = args[6];
        String filesWhichWillBeHashedOnThatPath= args[4];

        BufferedWriter logFileWriter = null;
        logFileWriter = new BufferedWriter(new FileWriter(logFilePath,true));

        // CERTIFICATE READING AND CREATING PUBLIC KEY
        PublicKey key = CertificateFactory.getInstance("X.509").generateCertificate(new FileInputStream(publicCertificatePath)).getPublicKey();


        //CONTENT AND SIGNATURE READING FROM REGISTER FILE
        Map<String, String> registerFileContent = File.readSignature(registerFilePath);

        // CONTENT HASHING
        byte[] contentDigest = Hash.getDigest(hashMethod, registerFileContent.get("content"));


        Signature sig = Signature.getInstance((hashMethod.equals("SHA-256") ? "SHA256" : "MD5") + "withRSA");
        sig.initVerify(key);
        sig.update(contentDigest);
        boolean isCorrect = sig.verify(Base64.getDecoder().decode(registerFileContent.get("signature")));

        //VERIFY DOGRUYSA
        if(isCorrect){
            AtomicBoolean isThereChange = new AtomicBoolean(false);
            Map<String, String> files = Arrays.stream(registerFileContent.get("content").split("\n")).collect(Collectors.toMap(o -> o.split(" ")[0], o -> o.split(" ")[1]));


            //PATH DEKI FILE LAR ILE REGISTRY FILE ICINDEKI FILE LARIN HASH DEGERLERINI KIYASLAMA VE SONUCA GORE LOG YAZMA
            Stream<Path> walk = Files.walk(Paths.get(filesWhichWillBeHashedOnThatPath));
            BufferedWriter finalLogFileWriter = logFileWriter;
            walk.filter(Files::isRegularFile)
                    .forEach(
                            file -> {
                                String fileName = file.toString();
                                if(!files.containsKey(fileName)){
                                    try {
                                        finalLogFileWriter.write(getCurrentTimeStamp()+": "+fileName+" is "+ChangeType.CREATED+"\n");
                                        finalLogFileWriter.flush();
                                        isThereChange.set(true);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                }else{
                                    String content = File.read(fileName);
                                    byte[] digest = Hash.getDigest(hashMethod, content);
                                    if(!Arrays.equals(digest,Base64.getDecoder().decode(files.get(fileName)))){
                                        try {
                                            finalLogFileWriter.write(getCurrentTimeStamp()+": "+fileName+" is "+ChangeType.ALTERED+"\n");
                                            finalLogFileWriter.flush();
                                            isThereChange.set(true);
                                        } catch (IOException e) {
                                            e.printStackTrace();
                                        }
                                    }
                                    files.remove(fileName);
                                }
                            }
                    );
            if(files.keySet().size() > 0){
                for (String deletedFiles : files.keySet()) {
                    finalLogFileWriter.write(getCurrentTimeStamp()+": "+deletedFiles+" is "+ChangeType.DELETED+"\n");
                    finalLogFileWriter.flush();
                }
            }else if(!isThereChange.get()){
                finalLogFileWriter.write(getCurrentTimeStamp() + ": The directory is checked and no change is detected!\n");
                finalLogFileWriter.flush();
            }

            //VERIFY DOGRU DEGILSE
        }else{
            logFileWriter.write(getCurrentTimeStamp()+": Registry file verification failed");
            logFileWriter.flush();
            System.exit(1);
        }
    }

    private static String getCurrentTimeStamp(){
        return new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Timestamp(System.currentTimeMillis()));
    }
}
