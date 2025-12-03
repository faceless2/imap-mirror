package com.bfo.imap;

import java.io.*;
import java.util.*;
import java.net.*;
import java.security.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import com.bfo.json.*;
import jakarta.mail.*;
import jakarta.mail.internet.*;


public class Main {

    private Json config;

    public static void main(String[] args) throws Exception {
        List<String> accounts = null;
        Json config = null;
        boolean debug = false;
        for (int i=0;i<args.length;i++) {
            String s = args[i];
            if (s.equals("--config") && i + 1 < args.length && config == null) {
                config = Json.read(new YamlReader().setInput(new FileInputStream(args[++i])));
            } else if (s.equals("--account") && i + 1 < args.length && config == null) {
                if (accounts == null) {
                    accounts = new ArrayList<String>();
                }
                accounts.add(args[++i]);
            } else if (s.equals("--debug")) {
                debug = true;
            } else if (s.equals("-h") || s.equals("--help")) {
                usage(null);
            } else {
                usage("Unknown argument \"" + s + "\"");
            }
        }
        if (config == null) {
            usage("No configuration specified");
        }
        if (debug) {
            config.put("debug", true);
        }

        Main main = new Main();
        main.configure(config);
        main.log("Started at " + new Date());
        try {
            boolean ok = main.process(accounts);
            if (ok) {
                main.log("Complete at " + new Date());
            } else {
                main.log("Incomplete at " + new Date());
            }
        } catch (Exception e) {
            main.log("Failed at " + new Date());
            throw e;
        }
    }

    Main() {
    }

    void configure(Json config) {
        if (config == null || !config.isMap() || !config.isMap("accounts")) {
            throw new IllegalArgumentException("Invalid configuration");
        }
        this.config = config;
    }

    boolean process(List<String> accounts) throws IOException, MessagingException, GeneralSecurityException {
        if (accounts == null) {
            accounts = new ArrayList<String>();
            for (Object o : config.mapValue("accounts").keySet()) {
                if (o instanceof String) {
                    accounts.add((String)o);
                }
            }
        }
        boolean ok = true;
        for (String s : accounts) {
            Json json = config.get("accounts").get(s);
            if (json == null) {
                error("No account \"" + s + "\"");
            }
            if (!json.isString("directory")) {
                error("No directory for \"" + s + "\"");
            }
            Path root = Paths.get(".").resolve(json.stringValue("directory"));
            if (!Files.isDirectory(root)) {
                Files.createDirectory(root);
            }
            Mirror mirror = new Mirror(s, this);
            mirror.initialize(root, json);
            ok &= mirror.process();
        }
        return ok;
    }

    private static void usage(String message) {
        if (message != null) {
            System.out.println("ERROR: " + message);
        }
        System.out.println("Usage: java -jar ImapMirror.jar [--config <config-yaml>] [--debug] [--account <account> ...]\n");
        System.exit(message == null ? 0 : -1);
    }

    void log(String message) {
        System.out.println(message);
    }

    void error(String message) {
        System.out.println("ERROR: " + message);
        System.exit(-1);
    }

    void progress(String name, int oldCount, int linkCount, int newCount, int total, boolean force) {
        boolean interactive = System.console() != null;
        boolean done = oldCount + linkCount + newCount == total;
        final float len = 100;
        if (!interactive && !done && !force && (newCount + linkCount == 0 || Math.floor((oldCount + linkCount + newCount) * len / total) == Math.floor((oldCount + linkCount + newCount - 1) * len / total))) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        int c0 = (int)Math.floor((oldCount + linkCount) * len / total);
        int c1 = (int)Math.floor(newCount * len / total);
        int c2 = (int)len - c0 - c1;
        sb.append(name);
        sb.append(": ");
        if (interactive) {
            while (c0-- > 0) {
                sb.append("#");
            }
            while (c1-- > 0) {
                sb.append("*");
            }
            while (c2-- > 0) {
                sb.append(".");
            }
            sb.append("  (");
        }
        if (oldCount > 0) {
            sb.append(oldCount);
            sb.append(" existing");
        }
        if (linkCount > 0) {
            if (oldCount > 0) {
                sb.append(", ");
            }
            sb.append(linkCount);
            sb.append(" shared");
        }
        if (oldCount > 0 || linkCount > 0) {
            sb.append(", ");
        }
        sb.append(newCount);
        sb.append(" new");
        sb.append(" of ");
        sb.append(total);
        if (interactive) {
            sb.append(")");
        }
        sb.append(done || !interactive ? "\n" : "\r");
        System.out.print(sb);
        System.out.flush();
    }

}
