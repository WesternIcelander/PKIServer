package io.siggi.pkiserver;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Sends alerts by email with a minimal SMTP client (RFC 5321): implicit TLS, STARTTLS (required
 * when configured, never silently skipped) or plain, optional {@code AUTH PLAIN}. TLS uses the
 * JDK's default trust store and verifies the host name.
 */
final class SmtpSink implements NotificationSink {
    private static final int TIMEOUT_MILLIS = 30_000;

    private final Config.Email email;
    private final SSLSocketFactory tlsFactory;

    SmtpSink(Config.Email email) {
        this(email, (SSLSocketFactory) SSLSocketFactory.getDefault());
    }

    SmtpSink(Config.Email email, SSLSocketFactory tlsFactory) {
        this.email = email;
        this.tlsFactory = tlsFactory;
    }

    @Override
    public String name() {
        return "email";
    }

    @Override
    public void send(String server, List<Alert> alerts) throws IOException {
        String message = message(server, alerts);
        Socket socket = new Socket();
        try {
            socket.connect(new InetSocketAddress(email.host(), email.port()), TIMEOUT_MILLIS);
            socket.setSoTimeout(TIMEOUT_MILLIS);
            if (email.security().equals("tls")) socket = startTls(socket);
            Conversation c = new Conversation(socket);
            c.expect(220);
            List<String> ehlo = c.command("EHLO " + localName(), 250);
            if (email.security().equals("starttls")) {
                if (ehlo.stream().noneMatch(l -> l.toUpperCase(java.util.Locale.ROOT).startsWith("STARTTLS"))) {
                    throw new IOException("SMTP server does not offer STARTTLS");
                }
                c.command("STARTTLS", 220);
                socket = startTls(socket);
                c = new Conversation(socket);
                c.command("EHLO " + localName(), 250);
            }
            if (email.username() != null) {
                String token = Base64.getEncoder().encodeToString(
                        ("\0" + email.username() + "\0" + email.password()).getBytes(StandardCharsets.UTF_8));
                c.command("AUTH PLAIN " + token, 235);
            }
            c.command("MAIL FROM:<" + email.from() + ">", 250);
            for (String to : email.to()) c.command("RCPT TO:<" + to + ">", 250, 251);
            c.command("DATA", 354);
            c.write(message + ".\r\n");
            c.expect(250);
            try {
                c.command("QUIT", 221);
            } catch (IOException ignored) {
                // Delivered already.
            }
        } finally {
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private Socket startTls(Socket plain) throws IOException {
        SSLSocket tls = (SSLSocket) tlsFactory.createSocket(plain, email.host(), email.port(), true);
        SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(params);
        tls.setSoTimeout(TIMEOUT_MILLIS);
        tls.startHandshake();
        return tls;
    }

    private static String localName() {
        return "pkiserver";
    }

    /** The full message (headers + base64 body), CRLF line endings, ending with CRLF. */
    String message(String server, List<Alert> alerts) {
        StringBuilder sb = new StringBuilder();
        sb.append("From: ").append(email.from()).append("\r\n");
        sb.append("To: ").append(String.join(", ", email.to())).append("\r\n");
        sb.append("Subject: ").append(encodeHeader(Notifier.subject(server, alerts))).append("\r\n");
        sb.append("Date: ").append(DateTimeFormatter.RFC_1123_DATE_TIME.format(ZonedDateTime.now(ZoneOffset.UTC)))
                .append("\r\n");
        String domain = email.from().substring(email.from().indexOf('@') + 1);
        sb.append("Message-ID: <").append(UUID.randomUUID()).append('@').append(domain).append(">\r\n");
        sb.append("MIME-Version: 1.0\r\n");
        sb.append("Content-Type: text/plain; charset=UTF-8\r\n");
        sb.append("Content-Transfer-Encoding: base64\r\n");
        sb.append("Auto-Submitted: auto-generated\r\n");
        sb.append("\r\n");
        // Base64 lines never start with '.', so no dot-stuffing is needed.
        sb.append(Base64.getMimeEncoder().encodeToString(Notifier.body(alerts).getBytes(StandardCharsets.UTF_8)));
        sb.append("\r\n");
        return sb.toString();
    }

    /** RFC 2047-encodes a header value unless it is plain printable ASCII. */
    static String encodeHeader(String value) {
        if (value.chars().allMatch(ch -> ch >= 0x20 && ch < 0x7f)) return value;
        return "=?UTF-8?B?" + Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8)) + "?=";
    }

    /** Reads SMTP replies and writes commands on one socket. */
    private static final class Conversation {
        private final BufferedReader in;
        private final OutputStream out;

        Conversation(Socket socket) throws IOException {
            this.in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            this.out = socket.getOutputStream();
        }

        void write(String s) throws IOException {
            out.write(s.getBytes(StandardCharsets.UTF_8));
            out.flush();
        }

        List<String> command(String line, int... ok) throws IOException {
            write(line + "\r\n");
            String shown = line.startsWith("AUTH ") ? "AUTH" : line;
            return expect(shown, ok);
        }

        List<String> expect(int... ok) throws IOException {
            return expect("connect", ok);
        }

        /** Reads one (possibly multi-line) reply; returns its text lines after the code. */
        private List<String> expect(String after, int... ok) throws IOException {
            List<String> lines = new java.util.ArrayList<>();
            int code;
            while (true) {
                String line = in.readLine();
                if (line == null) throw new IOException("SMTP server closed the connection after " + after);
                if (line.length() < 3) throw new IOException("bad SMTP reply after " + after + ": " + line);
                try {
                    code = Integer.parseInt(line.substring(0, 3));
                } catch (NumberFormatException e) {
                    throw new IOException("bad SMTP reply after " + after + ": " + line);
                }
                lines.add(line.length() > 4 ? line.substring(4) : "");
                if (line.length() == 3 || line.charAt(3) != '-') break;
            }
            for (int c : ok) {
                if (c == code) return lines;
            }
            throw new IOException("SMTP server answered " + code + " " + String.join(" ", lines) + " to " + after);
        }
    }
}
