public class ApiCheck {
    public static void main(String[] args) {
        boolean ok = "sample".equals(new org.zeroturnaround.zip.ZipException("sample").getMessage());
        if (!ok) {
            throw new AssertionError("Unexpected library result");
        }
        System.out.println("PASS");
    }
}
