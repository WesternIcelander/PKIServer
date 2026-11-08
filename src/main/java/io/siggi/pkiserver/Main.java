package io.siggi.pkiserver;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {
    public static void main(String[] args) {
        Logging.configure();
        Logger log = Logging.get(Main.class);

        Path configFile = Path.of("config.json");
        Path dataDirOverride = null;
        List<String> command = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (!command.isEmpty()) {
                command.add(arg);
            } else if ((arg.equals("--config") || arg.equals("-c")) && i + 1 < args.length) {
                configFile = Path.of(args[++i]);
            } else if (arg.equals("--data-dir") && i + 1 < args.length) {
                dataDirOverride = Path.of(args[++i]);
            } else if (AdminCli.isCommand(arg)) {
                command.add(arg);
            } else {
                System.err.print(AdminCli.USAGE_TEXT);
                System.exit(AdminCli.USAGE);
                return;
            }
        }

        if (!command.isEmpty()) {
            // Admin command: only warnings from the store, the command prints its own output.
            Logger.getLogger("").setLevel(Level.WARNING);
            Path dataDir = dataDirOverride;
            if (dataDir == null) {
                Config config = loadConfig(configFile, log);
                if (config == null) {
                    System.exit(1);
                    return;
                }
                dataDir = config.dataDir();
            }
            System.exit(new AdminCli(dataDir, System.out, System.err).run(command));
            return;
        }
        if (dataDirOverride != null) {
            System.err.println("--data-dir is only for admin commands; set dataDir in the config file");
            System.exit(AdminCli.USAGE);
            return;
        }

        Config config = loadConfig(configFile, log);
        if (config == null) {
            System.exit(1);
            return;
        }

        PKIServer server = new PKIServer(config);
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop, "PKIServer-shutdown"));
        try {
            server.start();
        } catch (IOException e) {
            log.log(Level.SEVERE, "Failed to start", e);
            System.exit(1);
        }
    }

    /** The config, or null (after logging why) if it can't be loaded. */
    private static Config loadConfig(Path configFile, Logger log) {
        try {
            return Config.load(configFile);
        } catch (NoSuchFileException e) {
            log.severe("Config file not found: " + configFile.toAbsolutePath());
        } catch (IOException e) {
            log.log(Level.SEVERE, "Could not read config file " + configFile.toAbsolutePath(), e);
        } catch (Config.ConfigException e) {
            log.severe("Invalid config file " + configFile.toAbsolutePath() + ": " + e.getMessage());
        }
        return null;
    }
}
