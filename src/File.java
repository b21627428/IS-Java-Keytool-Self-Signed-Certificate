import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public abstract class File {


    public static String read(String fileName){
        BufferedReader reader = null;
        StringBuilder stringBuilder = null;
        try {
            reader = new BufferedReader(new FileReader(fileName));
            String line;
            stringBuilder = new StringBuilder();
            while ((line = reader.readLine())!= null){
                stringBuilder.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stringBuilder.toString();
    }
    public static String read2(String fileName){
        BufferedReader reader = null;
        StringBuilder stringBuilder = null;
        try {
            reader = new BufferedReader(new FileReader(fileName));
            String line;
            stringBuilder = new StringBuilder();
            while ((line = reader.readLine())!= null){
                stringBuilder.append(line+"\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return stringBuilder.toString();
    }


    public static Map<String,String> readSignature(String fileName){
        Map<String,String> map = new HashMap<>();
        String signature = "";
        BufferedReader reader = null;
        StringBuilder stringBuilder = null;
        try {
            reader = new BufferedReader(new FileReader(fileName));
            String line;
            stringBuilder = new StringBuilder();
            while ((line = reader.readLine())!= null){
                stringBuilder.append(line+"\n");
                signature = line;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        map.put("content", stringBuilder != null ? stringBuilder.substring(0, stringBuilder.length() - signature.length() -1) : null);
        map.put("signature",signature);
        return map;
    }

    public static boolean write(String fileName,String content){
        BufferedWriter writer = null;
        try {
            writer = new BufferedWriter(new FileWriter(fileName));
            writer.write(content);
            writer.flush();
            writer.close();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
