public class ApiCheck {
    public static void main(String[] args) {
        boolean ok = new net.lingala.zip4j.model.ZipParameters().isEncryptFiles() == false;
        if (!ok) {
            throw new AssertionError("Unexpected library result");
        }
        System.out.println("PASS");
    }
}
