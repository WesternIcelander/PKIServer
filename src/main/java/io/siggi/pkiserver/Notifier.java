package io.siggi.pkiserver;

import io.siggi.pkiserver.store.Store;

import java.io.IOException;
import java.net.InetAddress;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Periodically checks for {@link Alerts} and sends them through the configured
 * {@link NotificationSink}s.
 * <p>
 * An alert is sent when it first becomes active, then again every {@code repeatHours} while it
 * stays active (never again if that is 0). All alerts due at one check go out as a single
 * notification per sink. A sink that fails gets the same alerts again at the next check; each
 * sink keeps its own record, so one failing channel doesn't hold up or duplicate the other.
 * That record is kept in memory only: after a restart, active alerts are sent again.
 */
final class Notifier {
    private static final Logger log = Logging.get(Notifier.class);

    private final Store store;
    private final Clock clock;
    private final Duration coverageWarning;
    private final Duration certWarning;
    private final Duration checkInterval;
    private final Duration repeat;
    private final String serverName;
    private final List<NotificationSink> sinks;
    /** Per sink: alert key → when it was last sent. */
    private final Map<NotificationSink, Map<String, Instant>> sent = new HashMap<>();
    private ScheduledExecutorService executor;

    Notifier(Store store, Clock clock, Duration coverageWarning, Config.Notifications config,
             List<NotificationSink> sinks) {
        this.store = store;
        this.clock = clock;
        this.coverageWarning = coverageWarning;
        this.certWarning = Duration.ofDays(config.certExpiryWarningDays());
        this.checkInterval = Duration.ofMinutes(config.checkIntervalMinutes());
        this.repeat = Duration.ofHours(config.repeatHours());
        this.serverName = config.name() != null ? config.name() : defaultName();
        this.sinks = List.copyOf(sinks);
        for (NotificationSink sink : this.sinks) sent.put(sink, new HashMap<>());
    }

    /** The sinks configured in {@code config}: webhook and/or email. */
    static List<NotificationSink> sinks(Config.Notifications config) {
        List<NotificationSink> sinks = new ArrayList<>();
        if (config.webhook() != null) sinks.add(new WebhookSink(config.webhook()));
        if (config.email() != null) sinks.add(new SmtpSink(config.email()));
        return sinks;
    }

    private static String defaultName() {
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (IOException e) {
            return "PKIServer";
        }
    }

    String serverName() {
        return serverName;
    }

    /** Starts checking now and then every {@code checkIntervalMinutes}. */
    synchronized void start() {
        if (executor != null) throw new IllegalStateException("Already started");
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "PKIServer-notifier");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleWithFixedDelay(this::runSafely, 0, checkInterval.toMillis(), TimeUnit.MILLISECONDS);
        List<String> names = sinks.stream().map(NotificationSink::name).toList();
        log.info("Notifications via " + String.join(" and ", names) + ", checking every "
                + checkInterval.toMinutes() + " minute(s)");
    }

    /** Stops checking. Idempotent. */
    void stop() {
        ScheduledExecutorService exec;
        synchronized (this) {
            exec = executor;
        }
        if (exec == null) return;
        exec.shutdownNow();
        try {
            exec.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void runSafely() {
        try {
            runOnce(clock.instant());
        } catch (RuntimeException e) {
            log.log(Level.SEVERE, "Notification check failed", e);
        }
    }

    /**
     * Checks for alerts and sends the due ones.
     *
     * @return the alerts that were due, per sink name (whether or not sending them worked)
     */
    synchronized Map<String, List<Alert>> runOnce(Instant now) {
        List<Alert> active = Alerts.find(store, now, coverageWarning, certWarning);
        Set<String> activeKeys = new HashSet<>();
        for (Alert a : active) activeKeys.add(a.key());

        Map<String, List<Alert>> result = new HashMap<>();
        for (NotificationSink sink : sinks) {
            Map<String, Instant> last = sent.get(sink);
            // Forget alerts that ended, so they are sent again if they come back.
            last.keySet().retainAll(activeKeys);
            List<Alert> due = new ArrayList<>();
            for (Alert a : active) {
                Instant at = last.get(a.key());
                if (at == null || (!repeat.isZero() && !now.isBefore(at.plus(repeat)))) due.add(a);
            }
            if (due.isEmpty()) continue;
            result.put(sink.name(), due);
            try {
                sink.send(serverName, due);
                for (Alert a : due) last.put(a.key(), now);
                log.info("Sent " + due.size() + " alert(s) by " + sink.name());
            } catch (IOException | RuntimeException e) {
                log.log(Level.WARNING, "Could not send " + due.size() + " alert(s) by " + sink.name()
                        + ", retrying at the next check: " + e.getMessage());
            }
        }
        return result;
    }

    static String subject(String server, List<Alert> alerts) {
        return "PKIServer " + server + ": " + alerts.size() + (alerts.size() == 1 ? " alert" : " alerts");
    }

    static String body(List<Alert> alerts) {
        StringBuilder sb = new StringBuilder();
        for (Alert a : alerts) sb.append("- ").append(a.message()).append('\n');
        return sb.toString();
    }
}
