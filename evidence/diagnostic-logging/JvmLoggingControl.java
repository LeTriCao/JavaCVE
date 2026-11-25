import java.util.IdentityHashMap;

/** Exercise the archived logging code using the Java standard library. */
public class JvmLoggingControl {
    private static String stage = "START";

    private static void stage(String value) {
        stage = value;
        System.out.println("STAGE=" + value);
    }

    private static void exception(Throwable error) {
        System.out.println("EXCEPTION_STAGE=" + stage);
        System.out.println("EXCEPTION_CLASS=" + error.getClass().getName());
        System.out.println("EXCEPTION_MESSAGE_BEGIN");
        System.out.println(error.getMessage());
        System.out.println("EXCEPTION_MESSAGE_END");
        IdentityHashMap<Throwable, Boolean> seen = new IdentityHashMap<Throwable, Boolean>();
        Throwable cause = error;
        int index = 0;
        while (cause != null && !seen.containsKey(cause)) {
            seen.put(cause, Boolean.TRUE);
            System.out.println("CAUSE_" + index + "_CLASS=" + cause.getClass().getName());
            System.out.println("CAUSE_" + index + "_MESSAGE=" + cause.getMessage());
            cause = cause.getCause();
            index++;
        }
        if (cause != null) System.out.println("CAUSE_CYCLE=true");
        System.out.println("STACK_TRACE_BEGIN");
        error.printStackTrace(System.out);
        System.out.println("STACK_TRACE_END");
    }

    public static void main(String[] args) {
        System.out.println("JAVA_VERSION=" + System.getProperty("java.version"));
        System.out.println("JAVA_RUNTIME_VERSION=" + System.getProperty("java.runtime.version"));
        System.out.println("JAVA_VENDOR=" + System.getProperty("java.vendor"));
        System.out.println("JAVA_VM_NAME=" + System.getProperty("java.vm.name"));
        System.out.println("JAVA_HOME=" + System.getProperty("java.home"));
        System.out.println("JAVA_CLASSPATH=" + System.getProperty("java.class.path"));
        stage("VALID_INTEGER");
        System.out.println("PARSED_INTEGER=" + Integer.parseInt("42"));
        stage("INVALID_INTEGER");
        try {
            Integer.parseInt("example");
        } catch (NumberFormatException cause) {
            exception(new IllegalArgumentException("Invalid sample value", cause));
        }
    }
}
