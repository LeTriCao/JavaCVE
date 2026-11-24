public class ApiCheck {
    public static void main(String[] args) {
        boolean ok = "cba".equals(cn.hutool.core.util.StrUtil.reverse("abc"));
        if (!ok) {
            throw new AssertionError("Unexpected library result");
        }
        System.out.println("PASS");
    }
}
