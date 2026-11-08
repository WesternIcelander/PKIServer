package io.siggi.pkiserver;

import org.junit.jupiter.api.Test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class RateLimiterTest {
    @Test
    void burstThenSteadyRefill() {
        AtomicLong now = new AtomicLong(1_000);
        RateLimiter limiter = new RateLimiter(3, now::get);
        assertTrue(limiter.tryAcquire("a"));
        assertTrue(limiter.tryAcquire("a"));
        assertTrue(limiter.tryAcquire("a"));
        assertFalse(limiter.tryAcquire("a"));
        assertEquals(20, limiter.retryAfterSeconds("a"));

        // other keys have their own bucket
        assertTrue(limiter.tryAcquire("b"));

        now.addAndGet(TimeUnit.SECONDS.toNanos(19));
        assertFalse(limiter.tryAcquire("a"));
        assertEquals(1, limiter.retryAfterSeconds("a"));
        now.addAndGet(TimeUnit.SECONDS.toNanos(1));
        assertTrue(limiter.tryAcquire("a"));
        assertFalse(limiter.tryAcquire("a"));

        // refill is capped at the burst size
        now.addAndGet(TimeUnit.HOURS.toNanos(1));
        for (int i = 0; i < 3; i++) assertTrue(limiter.tryAcquire("a"));
        assertFalse(limiter.tryAcquire("a"));
    }

    @Test
    void idleBucketsArePruned() {
        AtomicLong now = new AtomicLong();
        RateLimiter limiter = new RateLimiter(1, now::get);
        for (int i = 0; i < 10_000; i++) assertTrue(limiter.tryAcquire("ip" + i));
        assertEquals(10_000, limiter.size());
        now.addAndGet(TimeUnit.MINUTES.toNanos(2));
        assertTrue(limiter.tryAcquire("new"));
        assertEquals(1, limiter.size());
    }

    @Test
    void rejectsNonPositiveRate() {
        assertThrows(IllegalArgumentException.class, () -> new RateLimiter(0));
    }
}
