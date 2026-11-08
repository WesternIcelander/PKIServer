package io.siggi.pkiserver;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * POSTs alerts as JSON:
 * <pre>
 * {
 *   "server": "pki.siggi.io",
 *   "text": "PKIServer pki.siggi.io: 1 alert\n- CRL coverage of ...",
 *   "alerts": [{"type": "crl-coverage-low", "slug": "tls2", "at": "...", "message": "..."}]
 * }
 * </pre>
 * {@code text} makes it usable as-is with Slack/Mattermost-style incoming webhooks. Any 2xx
 * response counts as delivered.
 */
final class WebhookSink implements NotificationSink {
    private static final Duration TIMEOUT = Duration.ofSeconds(30);

    private final Config.Webhook webhook;
    private final HttpClient client;

    WebhookSink(Config.Webhook webhook) {
        this.webhook = webhook;
        this.client = HttpClient.newBuilder()
                .connectTimeout(TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    @Override
    public String name() {
        return "webhook";
    }

    static JsonObject payload(String server, List<Alert> alerts) {
        JsonObject j = new JsonObject();
        j.addProperty("server", server);
        j.addProperty("text", Notifier.subject(server, alerts) + "\n" + Notifier.body(alerts));
        JsonArray a = new JsonArray();
        for (Alert alert : alerts) a.add(alert.toJson());
        j.add("alerts", a);
        return j;
    }

    @Override
    public void send(String server, List<Alert> alerts) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(webhook.url())
                .timeout(TIMEOUT)
                .header("Content-Type", "application/json; charset=utf-8")
                .POST(HttpRequest.BodyPublishers.ofString(payload(server, alerts).toString(), StandardCharsets.UTF_8));
        for (Map.Entry<String, String> h : webhook.headers().entrySet()) {
            b.setHeader(h.getKey(), h.getValue());
        }
        HttpResponse<Void> response;
        try {
            response = client.send(b.build(), HttpResponse.BodyHandlers.discarding());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted", e);
        } catch (IllegalArgumentException e) {
            throw new IOException(e.getMessage(), e);
        }
        if (response.statusCode() / 100 != 2) {
            throw new IOException("webhook answered HTTP " + response.statusCode());
        }
    }
}
