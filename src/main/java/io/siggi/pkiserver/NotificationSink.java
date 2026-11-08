package io.siggi.pkiserver;

import java.io.IOException;
import java.util.List;

/** A channel notifications are sent through (webhook, email). */
interface NotificationSink {
    /** Short name for logs, e.g. "webhook". */
    String name();

    /**
     * Sends one notification carrying {@code alerts} (never empty).
     *
     * @param server the server's name, to tell servers apart
     * @throws IOException if it could not be delivered; the alerts are retried at the next check
     */
    void send(String server, List<Alert> alerts) throws IOException;
}
