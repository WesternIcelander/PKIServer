package io.siggi.pkiserver.store;

import java.math.BigInteger;
import java.time.Instant;

/**
 * A CRL that was accepted as a pre-signed backup and later discarded. Only kept as a record
 * (in {@code discarded.json}) so its number can never be reused and its bytes are known.
 */
public record DiscardedCrl(BigInteger number, String sha256, Instant thisUpdate, Instant nextUpdate,
                           Instant discardedAt, String reason) {
}
