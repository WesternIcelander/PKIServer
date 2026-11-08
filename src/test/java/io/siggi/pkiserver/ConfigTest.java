package io.siggi.pkiserver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ConfigTest {
    private static final Path BASE = Path.of("/srv/pki");

    @Test
    void emptyObjectGivesDefaults() throws Exception {
        Config c = Config.parse("{}", BASE);
        assertEquals(8080, c.listen().getPort());
        assertTrue(c.listen().getAddress().isAnyLocalAddress());
        assertEquals(List.of(), c.trustedProxies());
        assertFalse(c.uploadsEnabled());
        assertEquals(BASE, c.dataDir());
        assertEquals(Config.Limits.DEFAULT, c.limits());
    }

    @Test
    void fullConfig() throws Exception {
        Config c = Config.parse("""
                {
                  "listen": "127.0.0.1:9000",
                  "trustedProxies": ["127.0.0.1", "10.0.0.0/8", "::1"],
                  "dataDir": "data",
                  "limits": {
                    "maxUploadBytes": 65536,
                    "uploadsPerMinutePerIp": 10,
                    "crlMaxFutureDays": 400,
                    "coverageWarningDays": 14
                  }
                }
                """, BASE);
        assertEquals("127.0.0.1", c.listen().getAddress().getHostAddress());
        assertEquals(9000, c.listen().getPort());
        assertEquals(List.of("127.0.0.1", "10.0.0.0/8", "::1"), c.trustedProxies());
        assertTrue(c.uploadsEnabled());
        assertEquals(BASE.resolve("data"), c.dataDir());
        assertEquals(new Config.Limits(65536, 10, 400, 14), c.limits());
    }

    @Test
    void partialLimitsKeepDefaults() throws Exception {
        Config c = Config.parse("{\"limits\": {\"coverageWarningDays\": 7}}", BASE);
        assertEquals(7, c.limits().coverageWarningDays());
        assertEquals(Config.Limits.DEFAULT.maxUploadBytes(), c.limits().maxUploadBytes());
    }

    @Test
    void absoluteDataDir() throws Exception {
        Config c = Config.parse("{\"dataDir\": \"/var/lib/pki\"}", BASE);
        assertEquals(Path.of("/var/lib/pki"), c.dataDir());
    }

    @Test
    void ipv6Listen() throws Exception {
        Config c = Config.parse("{\"listen\": \"[::1]:8443\"}", BASE);
        assertEquals(8443, c.listen().getPort());
        assertTrue(c.listen().getAddress().isLoopbackAddress());
    }

    @Test
    void rejectsBadInput() {
        String[] bad = {
                "[]",
                "{",
                "{\"lsten\": \"0.0.0.0:80\"}",
                "{\"listen\": \"0.0.0.0\"}",
                "{\"listen\": \"0.0.0.0:99999\"}",
                "{\"listen\": \"0.0.0.0:http\"}",
                "{\"listen\": \"::1:80\"}",
                "{\"listen\": 80}",
                "{\"trustedProxies\": \"127.0.0.1\"}",
                "{\"trustedProxies\": [1]}",
                "{\"trustedProxies\": [\"not-an-ip\"]}",
                "{\"trustedProxies\": [\"10.0.0.0/40\"]}",
                "{\"dataDir\": \"\"}",
                "{\"limits\": []}",
                "{\"limits\": {\"maxUploadBytes\": 0}}",
                "{\"limits\": {\"maxUploadBytes\": -5}}",
                "{\"limits\": {\"maxUploadBytes\": 1.5}}",
                "{\"limits\": {\"maxUploadBytes\": \"1\"}}",
                "{\"limits\": {\"bogus\": 1}}",
        };
        for (String json : bad) {
            assertThrows(Config.ConfigException.class, () -> Config.parse(json, BASE), json);
        }
    }

    @Test
    void loadResolvesDataDirAgainstConfigFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("config.json");
        Files.writeString(file, "{\"dataDir\": \"store\"}");
        Config c = Config.load(file);
        assertEquals(dir.toAbsolutePath().resolve("store"), c.dataDir());
    }

    @Test
    void deploymentExampleConfigIsValid() throws Exception {
        Config c = Config.load(Path.of("deploy/config.example.json"));
        assertEquals(8080, c.listen().getPort());
        assertTrue(c.uploadsEnabled());
        assertEquals(List.of("172.30.0.2"), c.trustedProxies());
        assertEquals(Path.of("/data"), c.dataDir());
    }
}
