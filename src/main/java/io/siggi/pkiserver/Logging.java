package io.siggi.pkiserver;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.logging.Formatter;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/** Sends all {@code java.util.logging} output to stdout, one line per record. */
public final class Logging {
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    private Logging() {
    }

    /**
     * Installs the stdout handler. Call this first thing in {@code main}, before anything else
     * touches {@code java.util.logging}, so that {@link Manager} gets installed and log
     * records from shutdown hooks aren't lost.
     */
    public static void configure() {
        if (System.getProperty("java.util.logging.manager") == null) {
            System.setProperty("java.util.logging.manager", Manager.class.getName());
        }
        LogManager manager = LogManager.getLogManager();
        if (manager instanceof Manager m) {
            m.resetNow();
        } else {
            manager.reset();
        }
        Logger root = Logger.getLogger("");
        root.setLevel(Level.INFO);
        root.addHandler(new StdoutHandler(System.out));
    }

    public static Logger get(Class<?> clazz) {
        return Logger.getLogger(clazz.getName());
    }

    /**
     * The JDK's LogManager resets (removes all handlers) from its own shutdown hook, which
     * can run before ours and swallow the shutdown log lines. This one ignores that reset.
     */
    public static final class Manager extends LogManager {
        public Manager() {
        }

        @Override
        public void reset() {
            // Ignored, see class comment.
        }

        void resetNow() {
            super.reset();
        }
    }

    private static final class StdoutHandler extends Handler {
        private final PrintStream out;

        StdoutHandler(PrintStream out) {
            this.out = out;
            setFormatter(new LineFormatter());
        }

        @Override
        public void publish(LogRecord record) {
            if (!isLoggable(record)) return;
            String line = getFormatter().format(record);
            synchronized (out) {
                out.print(line);
                out.flush();
            }
        }

        @Override
        public void flush() {
            out.flush();
        }

        @Override
        public void close() {
            flush();
        }
    }

    static final class LineFormatter extends Formatter {
        @Override
        public String format(LogRecord record) {
            StringBuilder sb = new StringBuilder();
            sb.append(TIME.format(record.getInstant()))
                    .append(' ').append(record.getLevel().getName())
                    .append(' ').append(shortName(record.getLoggerName()))
                    .append(": ").append(formatMessage(record))
                    .append(System.lineSeparator());
            if (record.getThrown() != null) {
                StringWriter sw = new StringWriter();
                record.getThrown().printStackTrace(new PrintWriter(sw));
                sb.append(sw);
            }
            return sb.toString();
        }

        private static String shortName(String name) {
            if (name == null) return "-";
            int dot = name.lastIndexOf('.');
            return dot < 0 ? name : name.substring(dot + 1);
        }
    }
}
