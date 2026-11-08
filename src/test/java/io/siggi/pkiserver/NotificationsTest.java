package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpServer;
import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.Store;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class NotificationsTest {
    private static final Path BASE = Path.of("/srv/pki");
    private static final Duration COVERAGE_WARN = Duration.ofDays(30);
    private static final Duration CERT_WARN = Duration.ofDays(30);
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    private static KeyPair rootKey;
    private static KeyPair key2;

    @TempDir
    Path dir;

    @BeforeAll
    static void keys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        rootKey = gen.generateKeyPair();
        key2 = gen.generateKeyPair();
    }

    private static X509Certificate cert(String subject, String issuer, KeyPair subjectKey, KeyPair issuerKey,
                                        long serial, boolean ca, Instant notAfter) throws Exception {
        JcaX509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(new X500Name(issuer),
                BigInteger.valueOf(serial), Date.from(NOW.minus(Duration.ofDays(400))), Date.from(notAfter),
                new X500Name(subject), subjectKey.getPublic());
        b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        return new JcaX509CertificateConverter().getCertificate(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKey.getPrivate())));
    }

    private static X509CRL crl(String issuer, KeyPair key, long number, Instant thisUpdate, Instant nextUpdate)
            throws Exception {
        X509v2CRLBuilder b = new X509v2CRLBuilder(new X500Name(issuer), Date.from(thisUpdate));
        b.setNextUpdate(Date.from(nextUpdate));
        b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(number)));
        return new JcaX509CRLConverter().getCRL(
                b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(key.getPrivate())));
    }

    /**
     * "root": valid 10 more years, CRL coverage for 5 more days, end-entity certs expiring in
     * 5 days (#2), 100 days (#3) and expired (#4). "old": expires in 10 days, stale CRL.
     */
    private Store store() throws Exception {
        Store store = Store.open(dir.resolve("data"));
        store.addSigningCert("root", cert("CN=Root", "CN=Root", rootKey, rootKey, 1, true,
                NOW.plus(Duration.ofDays(3650))));
        store.addCrl("root", crl("CN=Root", rootKey, 1, NOW.minus(Duration.ofDays(1)), NOW.plus(Duration.ofDays(5))),
                CrlState.CURRENT, NOW);
        KeyPair leafKey = key2;
        store.addEndEntityCert("root", cert("CN=soon.example", "CN=Root", leafKey, rootKey, 2, false,
                NOW.plus(Duration.ofDays(5))), NOW);
        store.addEndEntityCert("root", cert("CN=later.example", "CN=Root", leafKey, rootKey, 3, false,
                NOW.plus(Duration.ofDays(100))), NOW);
        store.addEndEntityCert("root", cert("CN=gone.example", "CN=Root", leafKey, rootKey, 4, false,
                NOW.minus(Duration.ofDays(1))), NOW);

        store.addSigningCert("old", cert("CN=Old", "CN=Old", key2, key2, 1, true, NOW.plus(Duration.ofDays(10))));
        store.addCrl("old", crl("CN=Old", key2, 7, NOW.minus(Duration.ofDays(10)), NOW.minus(Duration.ofDays(1))),
                CrlState.CURRENT, NOW);
        return store;
    }

    private static Config.Notifications notifications(int repeatHours) {
        return new Config.Notifications("test", 30, 60, repeatHours, null, null);
    }

    // ------------------------------------------------------------------ conditions

    @Test
    void findsTheConditions() throws Exception {
        List<Alert> alerts = Alerts.find(store(), NOW, COVERAGE_WARN, CERT_WARN);
        List<String> keys = alerts.stream().map(Alert::key).sorted().toList();
        assertEquals(List.of(
                "cert-expiring:root/2",
                "crl-coverage-low:root",
                "crl-stale:old",
                "signing-cert-expiring:old"), keys);
        Alert stale = alerts.stream().filter(a -> a.type().equals(Alert.TYPE_CRL_STALE)).findFirst().orElseThrow();
        assertTrue(stale.message().contains("#7"), stale.message());
        assertTrue(stale.message().contains("next CRL Number: 8"), stale.message());
        Alert coverage = alerts.stream().filter(a -> a.type().equals(Alert.TYPE_CRL_COVERAGE_LOW)).findFirst()
                .orElseThrow();
        assertEquals(NOW.plus(Duration.ofDays(5)), coverage.at());
        Alert leaf = alerts.stream().filter(a -> a.type().equals(Alert.TYPE_CERT_EXPIRING)).findFirst().orElseThrow();
        assertEquals("2", leaf.serial());
        assertTrue(leaf.message().contains("soon.example"), leaf.message());
    }

    @Test
    void expiredSigningCertIsStillReported() throws Exception {
        Store store = store();
        List<Alert> alerts = Alerts.find(store, NOW.plus(Duration.ofDays(20)), COVERAGE_WARN, CERT_WARN);
        Alert old = alerts.stream().filter(a -> a.key().equals("signing-cert-expiring:old")).findFirst()
                .orElseThrow();
        assertTrue(old.message().contains("expired"), old.message());
        // The leaf that expired in the meantime is no longer reported.
        assertTrue(alerts.stream().noneMatch(a -> a.key().equals("cert-expiring:root/2")));
        // Coverage of "root" ran out: reported as stale, not as running low.
        assertTrue(alerts.stream().anyMatch(a -> a.key().equals("crl-stale:root")));
        assertTrue(alerts.stream().noneMatch(a -> a.key().equals("crl-coverage-low:root")));
    }

    @Test
    void pendingCrlsExtendCoverage() throws Exception {
        Store store = store();
        store.addCrl("root", crl("CN=Root", rootKey, 2, NOW.plus(Duration.ofDays(4)), NOW.plus(Duration.ofDays(60))),
                CrlState.PENDING, NOW);
        List<Alert> alerts = Alerts.find(store, NOW, COVERAGE_WARN, CERT_WARN);
        assertTrue(alerts.stream().noneMatch(a -> a.key().equals("crl-coverage-low:root")));
    }

    // ------------------------------------------------------------------ notifier

    private static final class RecordingSink implements NotificationSink {
        final List<List<Alert>> sent = new ArrayList<>();
        boolean fail;

        @Override
        public String name() {
            return "recording";
        }

        @Override
        public void send(String server, List<Alert> alerts) throws IOException {
            if (fail) throw new IOException("down");
            sent.add(alerts);
        }
    }

    private static List<String> keys(List<Alert> alerts) {
        return alerts.stream().map(Alert::key).sorted().toList();
    }

    @Test
    void sendsOnceThenRepeats() throws Exception {
        RecordingSink sink = new RecordingSink();
        Notifier n = new Notifier(store(), Clock.systemUTC(), COVERAGE_WARN, notifications(24), List.of(sink));
        n.runOnce(NOW);
        assertEquals(1, sink.sent.size());
        assertEquals(4, sink.sent.get(0).size());

        n.runOnce(NOW.plus(Duration.ofHours(1)));
        assertEquals(1, sink.sent.size(), "nothing new within the repeat interval");

        n.runOnce(NOW.plus(Duration.ofHours(24)));
        assertEquals(2, sink.sent.size());
        assertEquals(4, sink.sent.get(1).size());
    }

    @Test
    void repeatZeroSendsOnlyOnce() throws Exception {
        RecordingSink sink = new RecordingSink();
        Notifier n = new Notifier(store(), Clock.systemUTC(), COVERAGE_WARN, notifications(0), List.of(sink));
        n.runOnce(NOW);
        n.runOnce(NOW.plus(Duration.ofDays(3)));
        assertEquals(1, sink.sent.size());
    }

    @Test
    void newAlertsGoOutAloneAndFailuresAreRetried() throws Exception {
        Store store = store();
        RecordingSink sink = new RecordingSink();
        Notifier n = new Notifier(store, Clock.systemUTC(), COVERAGE_WARN, notifications(24), List.of(sink));
        sink.fail = true;
        n.runOnce(NOW);
        assertEquals(0, sink.sent.size());
        sink.fail = false;
        n.runOnce(NOW.plus(Duration.ofMinutes(60)));
        assertEquals(1, sink.sent.size());
        assertEquals(4, sink.sent.get(0).size());

        // A leaf nearing expiry is added: only it is sent.
        store.addEndEntityCert("root", cert("CN=new.example", "CN=Root", key2, rootKey, 5, false,
                NOW.plus(Duration.ofDays(2))), NOW);
        n.runOnce(NOW.plus(Duration.ofMinutes(120)));
        assertEquals(2, sink.sent.size());
        assertEquals(List.of("cert-expiring:root/5"), keys(sink.sent.get(1)));
    }

    @Test
    void resolvedAlertIsSentAgainWhenItComesBack() throws Exception {
        Store store = store();
        RecordingSink sink = new RecordingSink();
        Notifier n = new Notifier(store, Clock.systemUTC(), COVERAGE_WARN, notifications(0), List.of(sink));
        n.runOnce(NOW);
        // A fresh CRL fixes "old"'s stale CRL.
        store.setCrlState("old", BigInteger.valueOf(7), CrlState.SUPERSEDED);
        store.addCrl("old", crl("CN=Old", key2, 8, NOW, NOW.plus(Duration.ofDays(90))), CrlState.CURRENT, NOW);
        n.runOnce(NOW.plus(Duration.ofMinutes(1)));
        assertEquals(1, sink.sent.size());
        // ... until it goes stale again.
        n.runOnce(NOW.plus(Duration.ofDays(91)));
        assertTrue(sink.sent.stream().skip(1).flatMap(List::stream).anyMatch(a -> a.key().equals("crl-stale:old")));
    }

    // ------------------------------------------------------------------ webhook

    @Test
    void webhookPostsJson() throws Exception {
        HttpServer http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        AtomicReference<String> body = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        http.createContext("/hook", ex -> {
            body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            auth.set(ex.getRequestHeaders().getFirst("Authorization"));
            ex.sendResponseHeaders(204, -1);
            ex.close();
        });
        http.createContext("/broken", ex -> {
            ex.sendResponseHeaders(500, -1);
            ex.close();
        });
        http.start();
        try {
            String base = "http://127.0.0.1:" + http.getAddress().getPort();
            List<Alert> alerts = Alerts.find(store(), NOW, COVERAGE_WARN, CERT_WARN);
            new WebhookSink(new Config.Webhook(URI.create(base + "/hook"), Map.of("Authorization", "Bearer x")))
                    .send("pki.test", alerts);
            assertEquals("Bearer x", auth.get());
            JsonObject j = JsonParser.parseString(body.get()).getAsJsonObject();
            assertEquals("pki.test", j.get("server").getAsString());
            assertTrue(j.get("text").getAsString().startsWith("PKIServer pki.test: 4 alerts"));
            JsonArray a = j.getAsJsonArray("alerts");
            assertEquals(4, a.size());
            assertTrue(a.asList().stream().anyMatch(e -> e.getAsJsonObject().get("type").getAsString()
                    .equals("crl-stale")));

            WebhookSink broken = new WebhookSink(new Config.Webhook(URI.create(base + "/broken"), Map.of()));
            IOException e = assertThrows(IOException.class, () -> broken.send("pki.test", alerts));
            assertTrue(e.getMessage().contains("500"));
        } finally {
            http.stop(0);
        }
    }

    // ------------------------------------------------------------------ email

    /** A one-connection SMTP server that records the session. */
    private static CompletableFuture<List<String>> fakeSmtp(ServerSocket server) {
        return CompletableFuture.supplyAsync(() -> {
            List<String> log = new ArrayList<>();
            try (Socket s = server.accept()) {
                s.setSoTimeout(10_000);
                BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(),
                        StandardCharsets.UTF_8));
                OutputStream out = s.getOutputStream();
                out.write("220 fake ESMTP\r\n".getBytes(StandardCharsets.US_ASCII));
                boolean data = false;
                String line;
                while ((line = in.readLine()) != null) {
                    log.add(line);
                    String reply;
                    if (data) {
                        if (!line.equals(".")) continue;
                        data = false;
                        reply = "250 queued";
                    } else if (line.startsWith("EHLO")) {
                        reply = "250-fake\r\n250-AUTH PLAIN\r\n250 8BITMIME";
                    } else if (line.startsWith("AUTH PLAIN")) {
                        reply = "235 ok";
                    } else if (line.equals("DATA")) {
                        data = true;
                        reply = "354 go";
                    } else if (line.equals("QUIT")) {
                        out.write("221 bye\r\n".getBytes(StandardCharsets.US_ASCII));
                        break;
                    } else {
                        reply = "250 ok";
                    }
                    out.write((reply + "\r\n").getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            return log;
        });
    }

    @Test
    void emailIsSentOverSmtp() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<List<String>> session = fakeSmtp(server);
            Config.Email email = new Config.Email("127.0.0.1", server.getLocalPort(), "none", "pki", "secret",
                    "pki@example.com", List.of("a@example.com", "b@example.com"));
            List<Alert> alerts = Alerts.find(store(), NOW, COVERAGE_WARN, CERT_WARN);
            new SmtpSink(email).send("pki.test", alerts);
            List<String> log = session.get(10, TimeUnit.SECONDS);

            assertTrue(log.get(0).startsWith("EHLO "));
            String token = Base64.getEncoder().encodeToString("\0pki\0secret".getBytes(StandardCharsets.UTF_8));
            assertTrue(log.contains("AUTH PLAIN " + token));
            assertTrue(log.contains("MAIL FROM:<pki@example.com>"));
            assertTrue(log.contains("RCPT TO:<a@example.com>"));
            assertTrue(log.contains("RCPT TO:<b@example.com>"));
            assertTrue(log.contains("Subject: PKIServer pki.test: 4 alerts"));
            assertEquals("QUIT", log.get(log.size() - 1));

            int blank = log.indexOf("");
            int end = log.lastIndexOf(".");
            String body = new String(Base64.getMimeDecoder().decode(String.join("", log.subList(blank + 1, end))),
                    StandardCharsets.UTF_8);
            assertTrue(body.contains("CRL coverage of \"root\""), body);
            assertTrue(body.contains("soon.example"), body);
        }
    }

    @Test
    void starttlsIsRequiredWhenConfigured() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            CompletableFuture<List<String>> session = fakeSmtp(server);
            Config.Email email = new Config.Email("127.0.0.1", server.getLocalPort(), "starttls", null, null,
                    "pki@example.com", List.of("a@example.com"));
            IOException e = assertThrows(IOException.class,
                    () -> new SmtpSink(email).send("pki.test", Alerts.find(store(), NOW, COVERAGE_WARN, CERT_WARN)));
            assertTrue(e.getMessage().contains("STARTTLS"), e.getMessage());
            List<String> log = session.get(10, TimeUnit.SECONDS);
            assertTrue(log.stream().noneMatch(l -> l.startsWith("MAIL")), "nothing sent in the clear");
        }
    }

    @Test
    void nonAsciiSubjectIsEncoded() {
        assertEquals("plain", SmtpSink.encodeHeader("plain"));
        assertEquals("=?UTF-8?B?" + Base64.getEncoder().encodeToString("Grüße".getBytes(StandardCharsets.UTF_8))
                + "?=", SmtpSink.encodeHeader("Grüße"));
    }

    // ------------------------------------------------------------------ config

    @Test
    void configDefaultsToOff() throws Exception {
        assertFalse(Config.parse("{}", BASE).notifications().enabled());
        assertFalse(Config.parse("{\"notifications\": {}}", BASE).notifications().enabled());
    }

    @Test
    void fullNotificationConfig() throws Exception {
        Config c = Config.parse("""
                {"notifications": {
                  "name": "pki.siggi.io",
                  "certExpiryWarningDays": 14,
                  "checkIntervalMinutes": 15,
                  "repeatHours": 0,
                  "webhook": {"url": "https://hooks.example.com/x", "headers": {"Authorization": "Bearer t"}},
                  "email": {"host": "smtp.example.com", "security": "tls", "username": "u", "password": "p",
                            "from": "pki@example.com", "to": "admin@example.com"}
                }}
                """, BASE);
        Config.Notifications n = c.notifications();
        assertTrue(n.enabled());
        assertEquals("pki.siggi.io", n.name());
        assertEquals(14, n.certExpiryWarningDays());
        assertEquals(15, n.checkIntervalMinutes());
        assertEquals(0, n.repeatHours());
        assertEquals(URI.create("https://hooks.example.com/x"), n.webhook().url());
        assertEquals(Map.of("Authorization", "Bearer t"), n.webhook().headers());
        assertEquals(465, n.email().port());
        assertEquals("tls", n.email().security());
        assertEquals(List.of("admin@example.com"), n.email().to());
        assertFalse(n.email().toString().contains("p,"), "password kept out of toString");
        assertEquals(2, Notifier.sinks(n).size());
    }

    @Test
    void emailDefaults() throws Exception {
        Config.Email e = Config.parse("""
                {"notifications": {"email": {"host": "mx", "from": "a@b.c", "to": ["d@e.f"]}}}
                """, BASE).notifications().email();
        assertEquals("starttls", e.security());
        assertEquals(587, e.port());
        assertNull(e.username());
    }

    @Test
    void invalidNotificationConfigs() {
        for (String bad : List.of(
                "{\"notifications\": []}",
                "{\"notifications\": {\"bogus\": 1}}",
                "{\"notifications\": {\"repeatHours\": -1}}",
                "{\"notifications\": {\"certExpiryWarningDays\": 0}}",
                "{\"notifications\": {\"webhook\": {}}}",
                "{\"notifications\": {\"webhook\": {\"url\": \"ftp://x/y\"}}}",
                "{\"notifications\": {\"webhook\": {\"url\": \"https://x/y\", \"headers\": {\"A\": \"b\\r\\nC: d\"}}}}",
                "{\"notifications\": {\"email\": {\"from\": \"a@b.c\", \"to\": \"d@e.f\"}}}",
                "{\"notifications\": {\"email\": {\"host\": \"mx\", \"to\": \"d@e.f\"}}}",
                "{\"notifications\": {\"email\": {\"host\": \"mx\", \"from\": \"a@b.c\"}}}",
                "{\"notifications\": {\"email\": {\"host\": \"mx\", \"from\": \"a@b.c\", \"to\": \"x>\\r\\nRCPT TO:<y@z\"}}}",
                "{\"notifications\": {\"email\": {\"host\": \"mx\", \"from\": \"a@b.c\", \"to\": \"d@e.f\", \"security\": \"ssl\"}}}",
                "{\"notifications\": {\"email\": {\"host\": \"mx\", \"from\": \"a@b.c\", \"to\": \"d@e.f\", \"username\": \"u\"}}}"
        )) {
            assertThrows(Config.ConfigException.class, () -> Config.parse(bad, BASE), bad);
        }
    }

    // ------------------------------------------------------------------ server

    @Test
    void serverSendsAlertsAtStartup() throws Exception {
        store(); // writes the data dir
        HttpServer http = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        CompletableFuture<String> body = new CompletableFuture<>();
        http.createContext("/hook", ex -> {
            body.complete(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            ex.sendResponseHeaders(200, -1);
            ex.close();
        });
        http.start();
        PKIServer server = new PKIServer(Config.parse("""
                {"listen": "127.0.0.1:0", "dataDir": "data",
                 "notifications": {"name": "it", "webhook": {"url": "http://127.0.0.1:%d/hook"}}}
                """.formatted(http.getAddress().getPort()), dir));
        try {
            server.start();
            JsonObject j = JsonParser.parseString(body.get(10, TimeUnit.SECONDS)).getAsJsonObject();
            assertEquals("it", j.get("server").getAsString());
            assertEquals(4, j.getAsJsonArray("alerts").size());
        } finally {
            server.stop();
            http.stop(0);
        }
    }
}
