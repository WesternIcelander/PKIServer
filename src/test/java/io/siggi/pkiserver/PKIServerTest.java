package io.siggi.pkiserver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.ConnectException;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

class PKIServerTest {
    @Test
    void startsServesAndStops(@TempDir Path dir) throws Exception {
        Path dataDir = dir.resolve("data");
        Config config = Config.parse("{\"listen\": \"127.0.0.1:0\", \"dataDir\": \"data\"}", dir);
        PKIServer server = new PKIServer(config);
        server.start();
        int port;
        try {
            port = server.getPort();
            assertTrue(port > 0);
            assertTrue(Files.isDirectory(dataDir), "data dir is created");

            HttpClient client = HttpClient.newHttpClient();
            HttpResponse<String> response = client.send(
                    HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/nothing-here")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals(404, response.statusCode());
        } finally {
            long t0 = System.nanoTime();
            server.stop();
            long millis = (System.nanoTime() - t0) / 1_000_000;
            // the HttpClient's idle keep-alive connection must not hold up shutdown
            assertTrue(millis < 3000, "stop took " + millis + " ms");
        }
        server.stop(); // idempotent
        assertThrows(ConnectException.class, () -> new Socket("127.0.0.1", port).close());
    }

    @Test
    void cannotStartTwice(@TempDir Path dir) throws Exception {
        PKIServer server = new PKIServer(Config.parse("{\"listen\": \"127.0.0.1:0\"}", dir));
        server.start();
        try {
            assertThrows(IllegalStateException.class, server::start);
        } finally {
            server.stop();
        }
    }
}
