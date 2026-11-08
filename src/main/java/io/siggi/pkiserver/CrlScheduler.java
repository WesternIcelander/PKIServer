package io.siggi.pkiserver;

import io.siggi.pkiserver.store.CrlState;
import io.siggi.pkiserver.store.SigningCert;
import io.siggi.pkiserver.store.Store;
import io.siggi.pkiserver.store.StoreException;
import io.siggi.pkiserver.store.StoredCrl;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Promotes pending (pre-signed) CRLs when their {@code thisUpdate} arrives.
 * <p>
 * For each signing certificate, once one or more pending CRLs are due, the highest-numbered due
 * one becomes current and the due ones it jumps over become superseded. Before promoting, rule 5
 * (no un-revoking) is checked against the current CRL: a due CRL that fails it is discarded
 * (recorded in {@code discarded.json} and logged) and the next-highest due CRL is considered; if
 * none passes, the current CRL stays. Every change goes through the {@link Store}, so it is
 * persisted, and is logged.
 * <p>
 * The background thread runs at start (catching up on anything that came due while the server
 * was down), then wakes at the earliest pending {@code thisUpdate}, at least once a minute, and
 * whenever {@link #wakeUp()} is called (after a pending CRL was uploaded).
 */
final class CrlScheduler {
    private static final Logger log = Logging.get(CrlScheduler.class);

    /** Longest sleep between runs, as a safety net. */
    static final Duration MAX_SLEEP = Duration.ofMinutes(1);
    /** Shortest sleep between runs, so a failing run can't spin. */
    private static final Duration MIN_SLEEP = Duration.ofMillis(200);

    private final Store store;
    private final Clock clock;
    private final Object monitor = new Object();
    private boolean wakeRequested;
    private boolean stopped;
    private Thread thread;

    CrlScheduler(Store store, Clock clock) {
        this.store = store;
        this.clock = clock;
    }

    /** Starts the background thread. */
    void start() {
        synchronized (monitor) {
            if (thread != null) throw new IllegalStateException("Already started");
            thread = new Thread(this::loop, "PKIServer-crl-scheduler");
            thread.setDaemon(true);
            thread.start();
        }
    }

    /** Stops the background thread and waits for it to finish its current run. Idempotent. */
    void stop() {
        Thread t;
        synchronized (monitor) {
            stopped = true;
            monitor.notifyAll();
            t = thread;
        }
        if (t == null || t == Thread.currentThread()) return;
        try {
            t.join(10_000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Makes the background thread run (and reschedule) now. */
    void wakeUp() {
        synchronized (monitor) {
            wakeRequested = true;
            monitor.notifyAll();
        }
    }

    private void loop() {
        while (true) {
            synchronized (monitor) {
                if (stopped) return;
                wakeRequested = false;
            }
            Instant next = null;
            try {
                next = runOnce(clock.instant());
            } catch (RuntimeException e) {
                log.log(Level.SEVERE, "CRL scheduler run failed", e);
            }
            Instant now = clock.instant();
            Duration sleep = MAX_SLEEP;
            if (next != null) {
                Duration until = Duration.between(now, next);
                if (until.compareTo(sleep) < 0) sleep = until;
            }
            if (sleep.compareTo(MIN_SLEEP) < 0) sleep = MIN_SLEEP;
            long deadline = System.nanoTime() + sleep.toNanos();
            synchronized (monitor) {
                try {
                    while (!stopped && !wakeRequested) {
                        long remaining = deadline - System.nanoTime();
                        if (remaining <= 0) break;
                        monitor.wait(Math.max(1L, remaining / 1_000_000L));
                    }
                } catch (InterruptedException e) {
                    return;
                }
            }
        }
    }

    /**
     * Promotes due CRLs of every signing certificate.
     *
     * @return the earliest {@code thisUpdate} of the CRLs still pending, or null if none is
     */
    Instant runOnce(Instant now) {
        Instant next = null;
        for (SigningCert sc : store.signingCerts()) {
            try {
                promoteDue(sc.slug(), now);
            } catch (IOException | StoreException e) {
                log.log(Level.SEVERE, "Could not update the CRLs of \"" + sc.slug() + "\"", e);
            }
            for (StoredCrl c : store.crls(sc.slug())) {
                if (c.state() == CrlState.PENDING && (next == null || c.thisUpdate().isBefore(next))) {
                    next = c.thisUpdate();
                }
            }
        }
        return next;
    }

    /**
     * Promotes the due pending CRLs of one signing certificate, as described in the class comment.
     *
     * @return the CRL that became current, or null if the current CRL didn't change
     */
    StoredCrl promoteDue(String slug, Instant now) throws IOException, StoreException {
        // Same lock as CrlUpload, so an upload can't interleave with a promotion.
        synchronized (store) {
            StoredCrl current = store.currentCrl(slug);
            List<StoredCrl> due = new ArrayList<>();
            for (StoredCrl c : store.crls(slug)) {
                if (c.state() != CrlState.PENDING) continue;
                if (current != null && c.number().compareTo(current.number()) < 0) {
                    // Can only happen after an interrupted promotion: never let it replace
                    // the newer current CRL.
                    store.setCrlState(slug, c.number(), CrlState.SUPERSEDED);
                    log.warning("Pending CRL #" + c.number() + " of \"" + slug
                            + "\" is older than the current CRL #" + current.number() + ", superseded it");
                    continue;
                }
                if (!c.thisUpdate().isAfter(now)) due.add(c);
            }
            if (due.isEmpty()) return null;
            due.sort(Comparator.comparing(StoredCrl::number).reversed());

            StoredCrl promote = null;
            for (StoredCrl candidate : due) {
                String unrevoked = current == null ? null : CrlUpload.unrevokedError(current, candidate.crl());
                if (unrevoked == null) {
                    promote = candidate;
                    break;
                }
                store.discardCrl(slug, candidate.number(), now, "failed rule 5 at promotion: " + unrevoked);
                log.warning("Discarded pending CRL #" + candidate.number() + " of \"" + slug
                        + "\" instead of making it current: " + unrevoked);
            }
            if (promote == null) {
                if (current != null) {
                    log.warning("CRL #" + current.number() + " of \"" + slug + "\" stays current");
                }
                return null;
            }

            // Supersede the ones jumped over first: if promoting then fails, they can't later
            // take effect over the CRL that should have become current.
            List<String> skipped = new ArrayList<>();
            for (StoredCrl c : due) {
                if (c.number().compareTo(promote.number()) < 0 && store.crl(slug, c.number()) != null) {
                    store.setCrlState(slug, c.number(), CrlState.SUPERSEDED);
                    skipped.add("#" + c.number());
                }
            }
            StoredCrl promoted = store.setCrlState(slug, promote.number(), CrlState.CURRENT);
            log.info("Pending CRL #" + promoted.number() + " of \"" + slug + "\" is now current (thisUpdate "
                    + promoted.thisUpdate() + ", nextUpdate " + promoted.nextUpdate() + ")"
                    + (current == null ? "" : ", superseding #" + current.number())
                    + (skipped.isEmpty() ? "" : "; skipped pending CRL(s) " + String.join(", ", skipped)));
            return promoted;
        }
    }
}
