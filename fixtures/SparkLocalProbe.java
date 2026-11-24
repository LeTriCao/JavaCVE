import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.Comparator;
import spark.Spark;

/** Local HTTP resource probe. All files are inside one managed temporary tree. */
public class SparkLocalProbe {
    static String fetch(int port, String path) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL("http://127.0.0.1:" + port + path).openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        int status = connection.getResponseCode();
        InputStream input = status < 400 ? connection.getInputStream() : connection.getErrorStream();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        if (input != null) { byte[] buf = new byte[4096]; int n; while ((n = input.read(buf)) != -1) output.write(buf, 0, n); input.close(); }
        connection.disconnect();
        return status + " " + output.toString("UTF-8");
    }
    public static void main(String[] args) throws Exception {
        Path root = Files.createTempDirectory("spark-local-probe-");
        Path publicDir = Files.createDirectory(root.resolve("public"));
        Files.write(publicDir.resolve("good.txt"), "LOCAL_CONTROL".getBytes("UTF-8"));
        Files.write(root.resolve("outside.txt"), "LOCAL_OUTSIDE_MARKER".getBytes("UTF-8"));
        int port;
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getByName("127.0.0.1"))) { port = socket.getLocalPort(); }
        try {
            Spark.ipAddress("127.0.0.1"); Spark.port(port);
            Spark.externalStaticFileLocation(publicDir.toString());
            Spark.get("/health", (request, response) -> "READY");
            Spark.awaitInitialization();
            System.out.println("ASSERT|control|ordinary_static_file|" + fetch(port, "/good.txt").equals("200 LOCAL_CONTROL"));
            String[] paths = {"/..%5coutside.txt", "/%2e%2e%5coutside.txt", "/../outside.txt"};
            for (int i = 0; i < paths.length; i++) {
                String observed = fetch(port, paths[i]);
                System.out.println("OBSERVED_" + i + "=" + observed);
                System.out.println("ASSERT|security|external_containment_" + i + "|" + !observed.contains("LOCAL_OUTSIDE_MARKER"));
            }
        } finally {
            Spark.stop();
            Thread.sleep(500);
            try (java.util.stream.Stream<Path> files = Files.walk(root)) {
                files.sorted(Comparator.reverseOrder()).forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException e) { throw new UncheckedIOException(e); } });
            }
        }
    }
}
