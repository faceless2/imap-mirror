package com.bfo.imap;

import java.io.*;
import java.util.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.*;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.nio.charset.*;
import com.bfo.json.*;
import jakarta.mail.*;
import jakarta.mail.internet.*;

/**
 * A mirror operation for a single email account
 */
public class Mirror {

    private final String accountName;
    private final Main main;
    private final Map<String,Json> folderinfo = new HashMap<>();          // folder name -> validity (derived from filename)
    private final Map<String,Path> bymsgid = new HashMap<>();             // msgid -> parent folder
    private Path root;
    private Json config;
    private Properties properties;
    private Map<String,String> oauth2config;

    /**
     * Create the mirror
     * @param accountName the name this account is known as
     * @param main the Main that created it
     */
    Mirror(String accountName, Main main) {
        this.accountName = accountName;
        this.main = main;
    }

    /**
     * Initialize the mirror
     * @param root the folder on the file-system to store any downloaded emailed
     * @parma config the configuration file
     */
    void initialize(Path root, Json config) {
        this.root = root;
        this.config = config;
    }

    /**
     * Process the mirror operation, downloading any new messages
     * @return true if the mirror completed, false if it was cancelled (by the server)
     */
    boolean process() throws IOException, MessagingException, GeneralSecurityException {
        scanExisting();
        Store store = connect();

        boolean done = true;
        Deque<Folder> q = new ArrayDeque<Folder>();
        q.add(store.getDefaultFolder());
        Folder folder;
        List<Map.Entry<Integer,Folder>> folders = new ArrayList<>();
        while ((folder = q.pollFirst()) != null) {
            q.addAll(Arrays.asList(folder.list()));
            if ((folder.getType() & Folder.HOLDS_MESSAGES) != 0) {
                String fullName = folder.getFullName();
                if (config.isList("skip")) {
                    for (Json j : config.listValue("skip")) {
                        if (j.isString()) {
                            String s = j.stringValue();
                            if (fullName.equals(s) || (s.endsWith(folder.getSeparator() + "*") && fullName.startsWith(s.substring(0, s.length() - 1)))) {
                                folder = null;
                                break;
                            }
                        }
                    }
                }
                if (folder != null) {
                    int order;
                    if (config.isList("order")) {
                        order  = 0;
                        for (Json j : config.listValue("order")) {
                            if (j.isString()) {
                                String s = j.stringValue();
                                if (s.equals("*") || fullName.equals(s) || (s.endsWith(folder.getSeparator() + "*") && fullName.startsWith(s.substring(0, s.length() - 1)))) {
                                    break;
                                }
                            }
                            order++;
                        }
                    } else {
                        order = 0;
                    }
                    for (int i=folders.size() - 1;i>=0;i--) {
                        if (folders.get(i).getKey() <= order) {
                            folders.add(i + 1, new AbstractMap.SimpleEntry<Integer,Folder>(order, folder));
                            folder = null;
                            break;
                        }
                    }
                    if (folder != null) {
                        folders.add(0, new AbstractMap.SimpleEntry<Integer,Folder>(order, folder));
                    }
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<Integer,Folder> e : folders) {
            folder = e.getValue();
            if (sb.isEmpty()) {
                sb.append("Preparing to download " + folders.size() + " folders: ");
            } else {
                sb.append(", ");
            }
            sb.append("\"");
            sb.append(folder.getFullName());
            sb.append("\"");
        }
        log(sb.toString());
        for (Map.Entry<Integer,Folder> e : folders) {
            folder = e.getValue();
            if (!processFolder(folder)) {
                log("Server closed connection");
                done = false;
                break;
            }
        }
        store.close();
        return done;
    }

    /**
     * See which messages have already been downloaded.
     * Files are stored in a subdirectory representing the folder, then the filename is the cleaned message ID
     * Populates "folderinfo" with the metadata for each folder, and "bymsgid" as a map of cleaned message IDs to folder name
     */
    private void scanExisting() throws IOException {
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            final List<Path> stack = new ArrayList<Path>();
            @Override public FileVisitResult visitFile(Path file, BasicFileAttributes atts) throws IOException {
                String name = file.getFileName().toString();
                if (name.equals(".imap")) {
                    InputStream in = null;
                    try {
                        in = Files.newInputStream(file);
                        Json j = Json.read(in);
                        String folder = root.relativize(file).getParent().toString();
                        folderinfo.put(folder, j);
                    } catch (Exception e) {
                    } finally {
                        if (in != null) in.close();
                    }
                } else if (name.charAt(0) != '.') {
                    String msgid = name;
                    Path parent = stack.get(stack.size() - 1);
                    bymsgid.put(msgid, parent);
                }
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes atts) throws IOException {
                if (dir.getFileName().toString().startsWith(".")) {
                     return FileVisitResult.SKIP_SUBTREE;
                }
                stack.add(dir);
                return FileVisitResult.CONTINUE;
            }
            @Override public FileVisitResult postVisitDirectory(Path dir, IOException e) throws IOException {
                stack.remove(stack.size() - 1);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * Connect to the server
     * This will search for and open a file called ".authority" in the root folder, which is a PKCS12
     * keystore containing encrypted data. This will be updated with the results of any login to the
     * server, eg with the OAuth2 access_token and refresh_token
     */
    private Store connect() throws IOException, MessagingException, GeneralSecurityException {
        final Json json = Json.read(config.toString());

        // Read the ".authority" file if it exists
        final Path authPath = root.resolve(json.isString("auth_file") ? json.stringValue("auth_file") : ".authority");
        String authPassword = json.stringValue("auth_password");
        if (Files.isReadable(authPath)) {
            InputStream in = null;
            try {
                in = Files.newInputStream(authPath);
                Json auth = Json.read(in);
                in.close();
                in = null;
                if (auth.isString("auth")) {
                    // Data in ".authority" is encrypted. Decrypt with "authPassword", prompting for it if required
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    if (authPassword == null) {
                        authPassword = new String(System.console().readPassword("Password to decrypt \"" + authPath + "\": "));
                    }
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    Key key = new SecretKeySpec(digest.digest(authPassword.getBytes(StandardCharsets.UTF_8)), "AES");
                    byte[] data = Base64.getDecoder().decode(auth.stringValue("auth"));
                    cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, data, 0, 12));
                    data = cipher.doFinal(data, 12, data.length - 12);
                    auth.put("auth", Json.read(new ByteArrayInputStream(data)));
                }
                // Merge data from ".authority" over existing configuration
                if (!json.has("auth")) {
                    json.put("auth", auth.get("auth"));
                } else {
                    for (Map.Entry<Object,Json> e : auth.mapValue("auth").entrySet()) {
                        json.get("auth").put(e.getKey(), e.getValue());
                    }
                }
            } catch (Exception e) {
                log("error reading authority file \"" + authPath + "\", ignoring (" + e.getMessage() + ")");
            } finally {
                if (in != null) in.close();
            }
        }

        // Begin configuring the connection to the server
        properties = new Properties();
        if (json.isMap("properties")) {
            for (Map.Entry<Object,Json> e : json.get("properties").mapValue().entrySet()) {
                if (e.getKey() instanceof String && !e.getValue().isList() && !e.getValue().isMap()) {
                    properties.setProperty((String)e.getKey(), e.getValue().stringValue());
                }
            }
        }
        String type = json.stringValue("type");
        if ("gmail".equals(type)) {
            setupGmail(json);
        } else {
            setupGeneric(json);
        }

        String server = json.stringValue("server");
        String email = json.stringValue("email");
        String password = json.stringValue("password");
        if (server == null) {
            error("No server specified");
        } else if (email == null) {
            error("No email specified");
        }

        boolean save = false;
        if (oauth2config != null) {
            // If this map is set, the server usses OAuth2. Do the auth process.
            // If any new tokens are returned, save them.
            OAuth2.SimpleCallbackHandler handler = new OAuth2.SimpleCallbackHandler();
            OAuth2 oauth = new OAuth2(handler);
            oauth.configure(oauth2config);
            Map<String,String> map = oauth.getAuthorization();
            if (oauth.isUpdated()) {
                json.put("auth", map);
                save = true;
            }
            password = map.get("access_token");
        }
        if (password == null) {
            error("No password specified");
        }
        if (save) {
            // Update the ".authority" file
            Json auth = Json.read("{}");
            if (authPassword == null) {
                // Not encrypted
                auth.put("auth", Json.read(json.get("auth").toString()));
            } else {
                // Encrypt the value first. No salt, adds nothing as anyone wanting to brute force could look in this file for the salt!
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                Key key = new SecretKeySpec(digest.digest(authPassword.getBytes(StandardCharsets.UTF_8)), "AES");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, key);
                byte[] iv = cipher.getIV();
                byte[] data = cipher.doFinal(json.get("auth").toString().getBytes(StandardCharsets.UTF_8));
                byte[] joined = new byte[iv.length + data.length];
                System.arraycopy(iv, 0, joined, 0, iv.length);
                System.arraycopy(data, 0, joined, iv.length, data.length);
                auth.put("auth", new String(Base64.getEncoder().encodeToString(joined)));
            }
            Path authPathTmp = Paths.get(authPath + ".tmp");
            Files.writeString(authPathTmp, auth.toString());
            Files.move(authPathTmp, authPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }

        // Open the session, connect to the store and return it.
        Session session = Session.getDefaultInstance(properties, null);
        session.setDebug(config.booleanValue("debug"));
        Store store = session.getStore("imaps");
        store.connect(server, email, password);
        return store;
    }

    /**
     * Process an individual folder, downloading any unloaded messages.
     *
     * An ".imap" file in the folder directory will be checked and updated with
     * a list of messages (storing uid and message-id).
     * Then iterate over that list, checking if the message has been downloaded already.
     * If it hasn't but a message of that ID exists in another folder, hard-link to it.
     * Otherwise download it.
     *
     * @return true if the folder completed, false if the connection was closed
     */
    boolean processFolder(final Folder folder) throws IOException, MessagingException {
        Path folderPath = null;
        for (Folder f = folder;f!=null;f=f.getParent()) {
            if (f.getName() != null && f.getName().length() > 0) {
                String name = clean(f.getName());
                if (folderPath == null) {
                    folderPath = Paths.get(name);
                } else {
                    folderPath = Paths.get(name).resolve(folderPath);
                }
            }
        }
        final String folderName = "\"" + folder.getFullName() + "\"";
        final String cleanFolderName = folderPath.toString();
        folderPath = folderPath == null ? root : root.resolve(folderPath);
        final Path metaPath = folderPath.resolve(".imap");

        // Verify or recreated folder metadata 
        long uidValidity = ((UIDFolder)folder).getUIDValidity();
        Json meta = folderinfo.get(cleanFolderName);
        if (meta == null || meta.longValue("uid_validity") != uidValidity || !meta.isList("messages")) {
            meta = Json.read("{}");
            meta.put("when", 0);
            meta.put("uid_validity", uidValidity);
            meta.put("messages", Json.read("[]"));
            folderinfo.put(cleanFolderName, meta);
        }
        final Json list = meta.get("messages");
        int size = list.size();
        long uid = size == 0 ? 0 : list.get(size - 1).get("uid").longValue();

        // Update the index: fetch any messages not in "messages" list
        long t = System.currentTimeMillis();
        folder.open(Folder.READ_ONLY);
        Message[] messages = uid == 0 ? folder.getMessages() : ((UIDFolder)folder).getMessagesByUID(uid + 1, UIDFolder.LASTUID);
        FetchProfile fp = new FetchProfile();
        fp.add(FetchProfile.Item.ENVELOPE);
        fp.add(UIDFolder.FetchProfileItem.UID);
        folder.fetch(messages, fp);
        for (Message message : messages) {
            uid = ((UIDFolder)folder).getUID(message);
            String messageId = ((MimeMessage)message).getMessageID();
            if (messageId.charAt(0) == '<' && messageId.charAt(messageId.length() - 1) == '>') {
                messageId = messageId.substring(1, messageId.length() - 1);
            }
            Json j = Json.read("{}");
            j.put("uid", uid);
            j.put("msgid", messageId);
            // Insert in order is free if they are already sorted, and required if they're not.
            for (int i=list.size();i>=0;i--) {
                Json j2 = i == 0 ? null : list.get(i - 1);
                if (j2 == null || j2.longValue("uid") < j.longValue("uid")) {
                    while (i < list.size()) {
                        j = list.put(i, j);
                        j2 = ++i < list.size() ? list.get(i) : null;
                    }
                    break;
                } else if (j2.longValue("uid") == j.longValue("uid")) {
                    j = null;
                    break;
                }
            }
            if (j != null) {
                list.put(list.size(), j);
            }
        }
        log(folderName + ": index was " + size + " messages, added " + (list.size() - size) + " in " + (System.currentTimeMillis() - t) + "ms, now " + list.size());
        if (list.size() == 0) {
            return true;
        }

        // Folder has messages. Proceed!
        Files.createDirectories(folderPath);
        meta.put("when", System.currentTimeMillis());
        Files.writeString(metaPath, meta.toString());

        try {
            int oldCount = 0, linkCount = 0, newCount = 0;
            progress(folderName, oldCount, linkCount, newCount, list.size(), true);
            for (int i=0;i<list.size();i++) {
                Json j = list.get(i);
                uid = j.longValue("uid");
                final String messageId = j.stringValue("msgid");
                final String cleanMessageId = clean(messageId);
                final Path messagePath = folderPath.resolve(cleanMessageId);
                if (Files.isReadable(messagePath)) {
                    // Message already exists in this folder
                    oldCount++;
                } else {
                    Path otherFolderPath = bymsgid.get(cleanMessageId);
                    if (otherFolderPath != null) {
                        // Message already exists in another folder, link to it
                        Path otherMessagePath = otherFolderPath.resolve(cleanMessageId);
                        try {
                            Files.createLink(messagePath, otherMessagePath);
                        } catch (UnsupportedOperationException e) {
                            Files.createSymbolicLink(messagePath, otherMessagePath);
                        }
                        linkCount++;
                    } else {
                        // Message needs to be downloaded
                        MimeMessage message = (MimeMessage)((UIDFolder)folder).getMessageByUID(uid);
                        Date date = message.getSentDate();
                        InputStream in = null;
                        OutputStream out = null;
                        Path tmpPath = folderPath.resolve(cleanMessageId + ".tmp");
                        try {
                            out = Files.newOutputStream(tmpPath);
                            message.writeTo(out);
                            out.close();
                            // Set date of mail file to sent date (unsent messages will be 1970-01-01)
                            Files.setLastModifiedTime(tmpPath, FileTime.fromMillis(date == null ? 0 : date.getTime()));
                            Files.setPosixFilePermissions(tmpPath, PosixFilePermissions.fromString("r--r--r--"));
                            Files.move(tmpPath, messagePath, StandardCopyOption.ATOMIC_MOVE);
                            tmpPath = null;
                            newCount++;
                            bymsgid.put(cleanMessageId, folderPath);
                        } catch (IOException e) {
                            if (e.getCause() instanceof MessagingException) {
                                throw (MessagingException)e.getCause();
                            }
                        } finally {
                            if (in != null) in.close();
                            if (out != null) out.close();
                            if (tmpPath != null) Files.delete(tmpPath);
                        }
                    }
                }
                progress(folderName, oldCount, linkCount, newCount, list.size(), false);
            }
        } catch (FolderClosedException e) {
            System.out.println();
            // This is normal; gmail in particular has resource limits and boots you out regularly
            return false;
        }
        return true;
    }

    private void log(String msg) {
        main.log("[" + accountName + "] " + msg);
    }

    private void error(String msg) {
        main.error("[" + accountName + "] " + msg);
    }

    private void progress(String name, int oldCount, int linkCount, int newCount, int total, boolean force) {
        main.progress("[" + accountName + "] " + name, oldCount, linkCount, newCount, total, force);
    }

    /**
     * Make a path segment safe to write to the file system.
     */
    private static String clean(String path) throws UnsupportedEncodingException {
        return URLEncoder.encode(path, "UTF-8");        // Arbitrary but works.
    }

    //-------------------------------------------------------------------------------------------
    // Configuration for different IMAP providers would go here
    //-------------------------------------------------------------------------------------------

    // Configure GMail.
    // GMail requires "redirect_uri", "client_id", "client_secret" to be set,
    //
    private void setupGmail(Json json) {
        if (!json.isString("email")) {
            error("missing \"email\"");
        }
        if (!json.isString("redirect_uri")) {
            error("missing \"redirect_uri\"");
        }
        if (!json.isString("client_id")) {
            error("missing \"client_id\"");
        }
        if (!json.isString("client_secret")) {
            error("missing \"client_secret\"");
        }
        if (!json.isString("server")) {
            json.put("server", "imap.gmail.com");
        }
        if (!json.isString("scope")) {
            json.put("scope", "https://mail.google.com/");
        }
        if (!json.isString("auth_uri")) {
            json.put("auth_uri", "https://accounts.google.com/o/oauth2/v2/auth");
        }
        if (!json.isString("token_uri")) {
            json.put("token_uri", "https://www.googleapis.com/oauth2/v4/token");
        }

        properties.put("mail.imap.ssl.enable", "true");
        properties.put("mail.imap.auth.mechanisms", "XOAUTH2");
        properties.put("mail.imaps.sasl.enable", "true");

        oauth2config = new HashMap<String,String>();
        oauth2config.put("debug", "true");
        oauth2config.put("server", json.stringValue("server"));
        oauth2config.put("auth_uri", json.stringValue("auth_uri"));
        oauth2config.put("token_uri", json.stringValue("token_uri"));
        oauth2config.put("redirect_uri", json.stringValue("redirect_uri"));
        oauth2config.put("client_id", json.stringValue("client_id"));
        oauth2config.put("client_secret", json.stringValue("client_secret"));
        oauth2config.put("authorization_method", "inline");
        oauth2config.put("scope", json.stringValue("scope"));
        oauth2config.put("protocol_auth_prompt", "consent");
        oauth2config.put("protocol_auth_access_type", "offline");
        oauth2config.put("protocol_auth_code_challenge_method", "plain");
        oauth2config.put("protocol_auth_access_state", "");
        if (json.isMap("auth")) {
            for (Map.Entry<Object,Json> e : json.mapValue("auth").entrySet()) {
                oauth2config.put("auth." + e.getKey(), e.getValue().stringValue());
            }
        }
    }

    private void setupGeneric(Json json) {
        if (json.booleanValue("tls")) {
            properties.put("mail.imap.ssl.enable", "true");
        }
        if (json.isNumber("port")) {
            properties.put("mail.imap.port", Integer.toString(json.intValue("port")));
        }
        if (json.isString("server")) {
            properties.put("mail.imap.host", json.stringValue("server"));
        }
    }

}
