public class ichecker {

    public static void main(String[] args) {

         try {
             switch (args[0]){
                 case "createCert":
                     CreateCert.work(args);
                     break;
                 case "createReg":
                     CreateReg.work(args);
                     break;
                 case "check":
                     Integrity.work(args);
                     break;
                 default:
             }
         }catch (Exception e){
             e.printStackTrace();
         }
    }
}
