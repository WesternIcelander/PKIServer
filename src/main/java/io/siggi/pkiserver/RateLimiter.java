package io.siggi.pkiserver;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Per-key token bucket: each key may do {@code perMinute} actions in a burst, and gets them
 * back at a steady rate of {@code perMinute} per minute.
 */
final class RateLimiter {
    private static final long MINUTE_NANOS = TimeUnit.MINUTES.toNanos(1);
    /** Prune full (idle) buckets once the map gets this big, so it can't grow without bound. */
    private static final int PRUNE_THRESHOLD = 10_000;

    private final int perMinute;
    private final LongSupplier nanoTime;
    private final Map<String, Bucket> buckets = new HashMap<>();

    private static final class Bucket {
        double tokens;
        long updated;
    }

    RateLimiter(int perMinute) {
        this(perMinute, System::nanoTime);
    }

    RateLimiter(int perMinute, LongSupplier nanoTime) {
        if (perMinute <= 0) throw new IllegalArgumentException("perMinute must be positive");
        this.perMinute = perMinute;
        this.nanoTime = nanoTime;
    }

    /** Takes one token for {@code key}; false if it has none left. */
    synchronized boolean tryAcquire(String key) {
        long now = nanoTime.getAsLong();
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            if (buckets.size() >= PRUNE_THRESHOLD) prune(now);
            bucket = new Bucket();
            bucket.tokens = perMinute;
            bucket.updated = now;
            buckets.put(key, bucket);
        } else {
            refill(bucket, now);
        }
        if (bucket.tokens < 1) return false;
        bucket.tokens -= 1;
        return true;
    }

    /** Seconds until {@code key} has a token again (at least 1). */
    synchronized long retryAfterSeconds(String key) {
        Bucket bucket = buckets.get(key);
        if (bucket == null) return 1;
        refill(bucket, nanoTime.getAsLong());
        double missing = 1 - bucket.tokens;
        if (missing <= 0) return 1;
        // the small epsilon keeps floating-point noise from rounding a whole second up
        return Math.max(1, (long) Math.ceil(missing * 60.0 / perMinute - 1e-6));
    }

    synchronized int size() {
        return buckets.size();
    }

    private void refill(Bucket bucket, long now) {
        long elapsed = now - bucket.updated;
        if (elapsed > 0) {
            bucket.tokens = Math.min(perMinute, bucket.tokens + (double) elapsed * perMinute / MINUTE_NANOS);
            bucket.updated = now;
        }
    }

    private void prune(long now) {
        for (Iterator<Bucket> it = buckets.values().iterator(); it.hasNext(); ) {
            Bucket bucket = it.next();
            refill(bucket, now);
            if (bucket.tokens >= perMinute) it.remove();
        }
    }
}
