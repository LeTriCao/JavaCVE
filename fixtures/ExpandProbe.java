import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;
import java.util.Comparator;
import java.util.zip.*;

/** Bounded CVE-2022-4244 probe. Every input and output stays in one temporary tree. */
public class ExpandProbe {
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("javacve-expand-");
        try {
            for (String entry : new String[]{"good.txt", "../outside.txt", "../out-sibling.txt"}) {
                Path out = root.resolve(entry.equals("../out-sibling.txt") ? "out" : "extract");
                Files.createDirectories(out);
                Path zip = root.resolve("input.zip");
                try (ZipOutputStream stream = new ZipOutputStream(Files.newOutputStream(zip))) {
                    stream.putNextEntry(new ZipEntry(entry));
                    stream.write("JAVACVE_LOCAL_CONTROL".getBytes("UTF-8"));
                    stream.closeEntry();
                }
                Class<?> expand = Class.forName("org.codehaus.plexus.util.Expand");
                Object instance = expand.getConstructor().newInstance();
                expand.getMethod("setSrc", File.class).invoke(instance, zip.toFile());
                expand.getMethod("setDest", File.class).invoke(instance, out.toFile());
                String state = "accepted";
                try {
                    expand.getMethod("execute").invoke(instance);
                } catch (InvocationTargetException exc) {
                    state = "rejected:" + exc.getCause().getClass().getSimpleName();
                }
                Path result = out.resolve(entry).normalize();
                System.out.println(entry + " => " + state + "; written=" + Files.exists(result));
                Files.deleteIfExists(result);
            }
        } finally {
            try (java.util.stream.Stream<Path> paths = Files.walk(root)) {
                paths.sorted(Comparator.reverseOrder()).forEach(path -> {
                    try { Files.deleteIfExists(path); } catch (java.io.IOException exc) { throw new java.io.UncheckedIOException(exc); }
                });
            }
        }
    }
}
