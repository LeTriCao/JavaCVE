public class ApiCheck {
    public static void main(String[] args) {
        boolean ok = "abc".equals(org.codehaus.plexus.util.StringUtils.reverse("cba"));
        if (!ok) {
            throw new AssertionError("Unexpected library result");
        }
        System.out.println("PASS");
    }
}
