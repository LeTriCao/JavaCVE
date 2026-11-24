public class ApiCheck {
    public static void main(String[] args) {
        boolean ok = "txt".equals(org.apache.commons.io.FilenameUtils.getExtension("notes.txt"));
        if (!ok) {
            throw new AssertionError("Unexpected library result");
        }
        System.out.println("PASS");
    }
}
