import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomDriver;

/** Harmless deserialization callback. No processes, network or filesystem access. */
public class XStreamLocalProbe {
    private static int callbacks;
    public static class Marker {
        public void touch() { callbacks++; }
    }
    public static void main(String[] args) {
        XStream stream = new XStream(new DomDriver());
        Object control = stream.fromXML("<string>LOCAL_CONTROL</string>");
        System.out.println("ASSERT|control|string_roundtrip|" + "LOCAL_CONTROL".equals(control));
        String xml = "<dynamic-proxy><interface>java.lang.Runnable</interface>"
            + "<handler class='java.beans.EventHandler'><target class='XStreamLocalProbe$Marker'/>"
            + "<action>touch</action></handler></dynamic-proxy>";
        boolean rejected = false;
        try {
            Runnable callback = (Runnable) stream.fromXML(xml);
            callback.run();
        } catch (com.thoughtworks.xstream.XStreamException error) {
            rejected = true;
            System.out.println("OBSERVED_EXCEPTION=" + error.getClass().getName());
        }
        System.out.println("OBSERVED_CALLBACKS=" + callbacks);
        System.out.println("ASSERT|security|untrusted_event_handler_blocked|" + (rejected && callbacks == 0));
    }
}
