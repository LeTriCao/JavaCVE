import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;

/** Ordinary API checks with fixed benign values; no CVE or caller-chain probes. */
public class OrdinaryXStreamProbe {
    private static void check(String name, boolean passed) {
        System.out.println("CONTROL|" + name + "|" + passed);
        if (!passed) throw new AssertionError(name);
    }

    public static void main(String[] args) {
        XStream stream = new XStream(new DomDriver());
        check("string_roundtrip", "JavaCVE ordinary value".equals(
            stream.fromXML(stream.toXML("JavaCVE ordinary value"))));
        check("empty_string_roundtrip", "".equals(stream.fromXML(stream.toXML(""))));
        check("integer_roundtrip", Integer.valueOf(42).equals(
            stream.fromXML(stream.toXML(Integer.valueOf(42)))));
    }
}
