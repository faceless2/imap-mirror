package com.bfo.imap;

import java.net.*;
import javax.net.ssl.*;
import java.security.*;
import java.io.*;
import java.nio.*;
import java.util.*;
import java.util.Base64;
import java.net.*;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;


/**
 * <p>
 * Represents a generic OAuth2 authorization process, without any external dependencies
 * </p><p>
 * To use this class you'll need to create a {@link CallbackHandler} to handle the
 * web-based initial OAuth2 login process.
 * The {@link SimpleCallbackHandler} is an instance of this which uses the
 * <code>com.sun.net.httpserver</code> package to create a transient HTTP (or HTTPS)
 * server which processes authorization requests.
 * </p><p>
 * You will also need to supply a <code>Map&lt;String,String&gt;</code> to the
 * {@link configure} method which configures the OAuth2 service. This map will be updated
 * with new state, such as access_token etc, and should be saved if {@link #isUpdated} is
 * true. The configuraiton is a map containing the following fields.
 * </p>
 * <ul>
 * <li><b>client_id</b> - a string representing the <code>client_id</code>, which is normally supplied by the service. Required</li>
 * <li><b>client_secret</b> - a string representing the <code>client_secret</code>, which is normally supplied by the service. Required</li>
 * <li><b>auth_uri</b> - the URL to call to retrieve an <i>authorization token</i>. Required</li>
 * <li><b>redirect_uri</b> - the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2">redirection endpoint URL</a>, a URL which will be preregistered with the OAuth2 service - for example <code>http://localhost/oauth2</code>. Required</li>
 * <li><b>token_uri</b> - the URL to call with the authorization token to retrieve an <i>access token</i>. Required</li>
 * <li><b>scope</b> - the <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.3">scope token</a>, a single string with one or more words seperated by spaces. Usually required by the service</li>
 * <li><b>authorization_method</b> - if the string "inline", the <code>client_id</code> and <code>client_secret</code> will be sent in the JSON object, otherwise they will be sent as an HTTP <code>Authorization: Bearer</code> header</li>
 * <li><b>protocol_auth_<i>nnn</i></b> - any extra strings to be included in requests to the "auth_uri" (key is <i>nnn</i>)</li>
 * <li><b>protocol_grant_<i>nnn</i></b> - any extra strings to be included in requests to the "token_uri" (key is <i>nnn</i>)</li>
 * <li><b>protocol_refresh_<i>nnn</i></b> - any extra strings to be included in requests to the "token_uri" when refreshing a token (key is <i>nnn</i>)</li>
 * </ul>
 *
 * <h3>Example use</h3>
 * <pre>
 * OAuth2.SimpleCallbackHandler handler = new OAuth2.SimpleCallbackHandler();
 * // The next three lines make the callback listen on HTTPS
 * KeyStore keystore = KeyStore.getInstance("PKCS12");
 * keystore.load(new FileInputStream("keystore.pkcs12"), "password".toCharArray());
 * handler.setSSLContext(keystore, args[1].toCharArray());
 *
 * OAuth2 oauth = new OAuth2(handler);
 * Map<String,String> map = new HashMap<String,String>();
 * map.put("client_id", "the client id");
 * map.put("client_secret", "the clent secret");
 * map.put("auth_uri", "https://oauth-sandbox.ssl.com/oauth2/authorize");
 * map.put("token_uri", "https://oauth-sandbox.ssl.com/oauth2/token");
 * map.put("redirect_uri", "https://localhost:9870/oauth_redirect");    // the redirect_uri registered with the service
 * map.put("scope", "service");
 * oauth.configure(map);
 * // time passes
 * Map&lt;String,String&gt; authmap = auth.getAuthorization());
 * if (auth.isUpdated()) {
 *     // the map now has an access_token and refresh_token - save it somewhere so it can be reused
 * }
 * String accessToken = authmap.get("access_token");
 * </pre>
 */
public class OAuth2 {

    private boolean debug;
    private final CallbackHandler handler;
    private final Random random;
    private Map<String,String> props;
    private String clientId;
    private String secret;
    private String authuri;
    private String tokenuri;
    private String redirecturi;
    private String scope;
    private boolean inlineAuthorization;
    private boolean needsSave;

    /**
     * Create a new OAuth2
     */
    public OAuth2(CallbackHandler handler) {
        this(null, handler);
    }

    /**
     * Create a new OAuth2
     * @param random the {@link SecureRandom} for random number generation, typically {@link ReportFactory#getRandom}
     * @param handler the {@link CallbackHandler} which must support {@link OAuth2Callback} objects, or null to use the one on the Report
     */
    public OAuth2(Random random, CallbackHandler handler) {
        if (random == null) {
            try {
                random = SecureRandom.getInstance("NativePRNGNonBlocking");
            } catch (NoSuchAlgorithmException e) {
                random = new SecureRandom();
            }
        }
        this.random = random;
        this.handler = handler;
    }

    /**
     * Load the OAuth2 configuration.
     * A reference to the supplied Json object is kept, and
     * the structure will be updated and should be saved if
     * {@link isUpdated} is true
     * @param json a Json which must have "client_id", "client_secret", "scope", "redirect_uri", "auth_uri" and "token_uri" strings. It may have an "authorization_method" string set to "inline"; It may have an "authorization" map with one or more of "access_token", "token_type", "refresh_token", "expires"; and it may have "protocol.auth", "protocol.grant" or "protocol.refresh" maps
     */
    public void configure(Map<String,String> props) {
        synchronized(props) {
            this.props = props;
            this.debug = "true".equals(props.get("debug"));
            if (!(props.get("auth_uri") instanceof String)) {
                throw new IllegalArgumentException("No auth_uri parameter");
            }
            if (!(props.get("token_uri") instanceof String)) {
                throw new IllegalArgumentException("No token_uri parameter");
            }
            if (!(props.get("redirect_uri") instanceof String)) {
                throw new IllegalArgumentException("No redirect_uri parameter");
            }
            if (!(props.get("client_id") instanceof String)) {
                throw new IllegalArgumentException("No client_id parameter");
            }
            if (!(props.get("client_secret") instanceof String)) {
                throw new IllegalArgumentException("No client_secret parameter");
            }
            if ("inline".equals(props.get("authorization_method"))) {
                inlineAuthorization = true;
            }
            authuri = (String)props.get("auth_uri");
            tokenuri = (String)props.get("token_uri");
            redirecturi = (String)props.get("redirect_uri");
            clientId = (String)props.get("client_id");
            secret = (String)props.get("client_secret");
            scope = (String)props.get("scope");

            if (!(props.get("auth.access_token") instanceof String)) {
                props.remove("auth.access_token");
            }
            long expiry = 0;
            if (props.get("auth.expires") instanceof String) {
                try {
                    expiry = Long.parseLong(props.get("auth.expires"));
                } catch (Exception e) {}
            } else if (props.get("auth.expires_in") instanceof String) {
                try {
                    expiry = Long.parseLong(props.get("auth.expires_in"));
                    expiry = System.currentTimeMillis() + expiry * 1000;
                } catch (Exception e) {}
            }
            if (expiry != 0 && System.currentTimeMillis() > expiry) {
                props.remove("auth.access_token");
                props.remove("auth.token_type");
            }
            handler.configure(this, props);
        }
    }

    /**
     * If the OAuth2 configuration supplied in {@link #load} has been updated
     * with new tokens, since the last time this method was called, return true.
     */
    public boolean isUpdated() {
        if (needsSave) {
            needsSave = false;
            return true;
        }
        return false;
    }

    private static void debug(String msg) {
        System.out.println(msg);
    }

    private static String buildURL(String cmd, Map<String,String> map) throws IOException {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        if (cmd != null) {
            sb.append(cmd);
        }
        for (Map.Entry<String,String> e : map.entrySet()) {
            String key = e.getKey();
            String val = e.getValue();
            if (key != null && val != null) {
                if (sb.length() > 0) {
                    sb.append(first ? '?' : '&');
                }
                first = false;
                sb.append(key);
                sb.append('=');
                sb.append(URLEncoder.encode(val, "UTF-8"));
            }
        }
        return sb.toString();
    }

    private static Map<String,List<String>> parseURLParameters(String value) {
        try {
            if (value == null || value.length() == 0) {
                return Collections.<String,List<String>>emptyMap();
            }
            Map<String,List<String>> map = new LinkedHashMap<String,List<String>>();
            String[] pairs = value.split("&");
            for (String s : pairs) {
                int i = s.indexOf("=");
                String key = i >= 0 ? URLDecoder.decode(s.substring(0, i), "UTF-8") : s;
                value = i >= 0 && i + 1 < s.length() ? URLDecoder.decode(s.substring(i + 1), "UTF-8") : null;
                List<String> list = map.get(key);
                if (list == null) {
                    map.put(key, list = Collections.<String>singletonList(value));
                } else {
                    if (list.size() == 1) {
                        map.put(key, list = new ArrayList<String>(list));
                    }
                    list.add(value);
                }
            }
            return map;
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }


    private String randomString(int len) {
        char[] c = new char[len];
        for (int i=0;i<c.length;i++) {
            c[i] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".charAt(random.nextInt(62));
        }
        return new String(c);
    }

    /**
     * Return the "access_token" from the {@link #getAuthorization} method.
     */
    public String getAccessToken() throws IOException {
        Map<String,String> map = getAuthorization();
        return map == null ? null : map.get("access_token");
    }

    /**
     * Return the authorization response from the OAuth2 server.
     * The returned Json should have "access_token" and other properties returned
     * from the server, except that "expires_in" is replaced with "expires" which is
     * milliseconds since the epoch, and "id_token", if present, has been decoded.
     * This method may block if the response needs to be requested or refreshed
     */
    public Map<String,String> getAuthorization() throws IOException {
        String access_token = null;
        String refresh_token = null;
        synchronized(props) {
            access_token = props.get("auth.access_token");
            refresh_token = props.get("auth.refresh_token");
        }
        if (access_token == null) {
            Map<String,Object> authorization = null;
            if (refresh_token != null) {
                Map<String,String> m = new LinkedHashMap<String,String>();
                synchronized(props) {
                    m.put("client_id", clientId);
                    m.put("client_secret", secret);
                    m.put("refresh_token", props.get("auth.refresh_token"));
                    m.put("grant_type", "refresh_token");
                    for (Map.Entry<String,String> e : props.entrySet()) {
                        if (e.getKey().startsWith("protocol_refresh_")) {
                            String key = e.getKey().substring(17);
                            String value = e.getValue() == null ? null : e.getValue().toString();
                            if (value != null) {
                                m.put(key, value);
                            }
                        }
                    }
                }
                authorization = send(tokenuri, m);
            } else {
                Map<String,String> m = new LinkedHashMap<String,String>();
                String codeVerifier = null;
                synchronized(props) {
                    m.put("response_type", "code");
                    if (scope != null) {
                        m.put("scope", scope);
                    }
                    m.put("client_id", clientId);
                    if (redirecturi != null) {
                        m.put("redirect_uri", redirecturi);
                    }
                    for (Map.Entry<String,String> e : new HashMap<String,String>(props).entrySet()) {
                        if (e.getKey().startsWith("protocol_auth_")) {
                            String key = e.getKey().substring(14);
                            String value = e.getValue() == null ? null : e.getValue().toString();
                            if (value != null) {
                                if (key.equals("code_challenge_method")) {
                                    if ("plain".equals(value)) {
                                        codeVerifier = randomString(64);
                                        m.put("code_challenge", codeVerifier);
                                        synchronized(props) {
                                            props.put("code_verifier", codeVerifier);
                                            props.put("code_challenge_method", value);
                                        }
                                    } else if ("S256".equals(value)) {
                                        codeVerifier = randomString(64);
                                        try {
                                            MessageDigest digest = MessageDigest.getInstance("SHA-256");
                                            m.put("code_challenge", Base64.getUrlEncoder().encodeToString(digest.digest(codeVerifier.getBytes("UTF-8"))));      // Base64 URL encoding https://www.oauth.com/oauth2-servers/pkce/authorization-request/
                                            m.put("code_challenge_method", value);
                                            synchronized(props) {
                                                props.put("code_verifier", codeVerifier);
                                                props.put("code_challenge_method", value);
                                            }
                                        } catch (NoSuchAlgorithmException e2) {
                                            throw new RuntimeException(e2);
                                        }
                                    }
                                } else if (key.equals("state")) {
                                    String state = randomString(64);
                                    m.put("state", state);
                                    synchronized(props) {
                                        props.put("state", state);
                                    }
                                } else {
                                    m.put(key, value);
                                }
                            }
                        }
                    }
                }
                String s = buildURL(authuri, m);

                Callback callback = new Callback(this, redirecturi, s, props);
                handler.callback(callback);
                String code = callback.getCode();
                if (code == null) {
                    throw new IOException("No code received");
                }

                m.clear();
                m.put("code", code);
                m.put("client_id", clientId);
                m.put("client_secret", secret);
                m.put("redirect_uri", redirecturi);
                m.put("grant_type", "authorization_code");
                if (codeVerifier != null) {
                    m.put("code_verifier", codeVerifier);
                }
                synchronized(props) {
                    for (Map.Entry<String,String> e : props.entrySet()) {
                        if (e.getKey().startsWith("protocol_grant_")) {
                            String key = e.getKey().substring(15);
                            String value = e.getValue() == null ? null : e.getValue().toString();
                            if (value != null) {
                                m.put(key, value);
                            }
                        }
                    }
                }
                authorization = send(tokenuri, m);
            }
            if (authorization.get("expires_in") instanceof Number) {
                try {
                    long expiry = ((Number)authorization.get("expires_in")).longValue();
                    expiry = System.currentTimeMillis() + expiry * 1000l;
                    authorization.put("expires", Long.valueOf(expiry));
                    authorization.remove("expires_in");
                } catch (Exception e) { }
            }
            if (authorization.get("id_token") instanceof String) {
                try {
                    byte[] bid = Base64.getDecoder().decode(((String)authorization.get("id_token")).replace("-", "+").replace("_", "/"));
                    authorization.put("id_token", new String(bid, "UTF-8"));
                } catch (Exception e) { }
            }
            synchronized(props) {
                for (Map.Entry<String,Object> e : authorization.entrySet()) {
                    props.put("auth." + e.getKey(), e.getValue().toString());
                }
            }
            handler.configurationUpdated(props);
            needsSave = true;
        }

        synchronized(props) {
            LinkedHashMap<String,String> out = new LinkedHashMap<String,String>();
            for (Map.Entry<String,String> e : props.entrySet()) {
                if (e.getKey().startsWith("auth.")) {
                    out.put(e.getKey().substring(5), e.getValue());
                }
            }
            return out;
        }
    }

    private Map<String,Object> send(String cmd, Map<String,String> m) throws IOException {
        HttpURLConnection con = (HttpURLConnection) new URL(cmd).openConnection();
        con.setDoOutput(true);
        con.setRequestMethod("POST");
        if (!inlineAuthorization) {
            m = new LinkedHashMap<String,String>(m);
            String clientId = m.remove("client_id");
            String clientSecret = m.remove("client_secret");
            String s = "Basic " + Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes("UTF-8"));
            con.setRequestProperty("Authorization", s); // Basic auth uses non-URL (standard) Base64 encoding
        }
        String uri = buildURL(null, m);
        if (debug) debug("send "+uri);
        con.getOutputStream().write(uri.getBytes("UTF-8"));
        con.getOutputStream().close();
        con.connect();
        try {
            ByteArrayOutputStream bout = new ByteArrayOutputStream();
            InputStream in = con.getInputStream();
            byte[] buf = new byte[8192];
            int l;
            while ((l=in.read(buf)) >= 0) {
                bout.write(buf, 0, l);
            }
            String json = new String(bout.toByteArray(), "UTF-8");
            if (debug) debug("receive "+json);
            @SuppressWarnings("unchecked") Map<String,Object> out = (Map<String,Object>)parseJson(CharBuffer.wrap(json));
            return out;
        } catch (Exception e) {
            StringBuilder sb = new StringBuilder();
            int c;
            InputStream in = con.getErrorStream();
            while ((c=in.read())>=0) {
                sb.append((char)c);
            }
            if (debug) debug(sb.toString());
            throw e;
        }
    }

    /**
     * A quick single-method JSON parser, intended to parse input which is expected to be valid.
     * Does not exacly match the JSON parsing rules for numbers.
     */
    private static Object parseJson(CharBuffer in) {
        int tell = in.position();
        try {
            char c;
            while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t') {
                tell++;
            }
            Object out;
            if (c == '{') {
                Map<String,Object> m = new LinkedHashMap<String,Object>();
                while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                if (c != '}') {
                    in.position(in.position() - 1);
                    do {
                        String key = (String)parseJson(in);
                        while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                        if (c == ':') {
                            m.put((String)key, parseJson(in));
                            tell = in.position();
                        } else {
                            throw new UnsupportedOperationException("expecting colon");
                        }
                        while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                        if (c != ',' && c != '}') {
                            throw new UnsupportedOperationException("expecting comma or end-map");
                        }
                    } while (c != '}');
                }
                out = m;
            } else if (c == '[') {
                List<Object> l = new ArrayList<Object>();
                while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                if (c != ']') {
                    in.position(in.position() - 1);
                    do {
                        l.add(parseJson(in));
                        tell = in.position();
                        while ((c=in.get()) == ' ' || c == '\n' || c == '\r' || c == '\t');
                        if (c != ',' && c != ']') {
                            throw new UnsupportedOperationException("expecting comma or end-list");
                        }
                    } while (c != ']');
                }
                out = l;
            } else if (c == '"') {
                StringBuilder sb = new StringBuilder();
                while ((c=in.get()) != '"') {
                    if (c == '\\') {
                        c = in.get();
                        switch (c) {
                            case 'n': c = '\n'; break;
                            case 'r': c = '\r'; break;
                            case 't': c = '\t'; break;
                            case 'b': c = '\b'; break;
                            case 'f': c = '\f'; break;
                            case 'u': c = (char)Integer.parseInt(in.subSequence(0, 4).toString(), 16); in.position(in.position() + 4); break;
                        }
                    }
                    sb.append(c);
                }
                out = sb.toString();
            } else if (c == 't' && in.get() == 'r' && in.get() == 'u' && in.get() == 'e') {
                out = Boolean.TRUE;
            } else if (c == 'f' && in.get() == 'a' && in.get() == 'l' && in.get() == 's' && in.get() == 'e') {
                out = Boolean.FALSE;
            } else if (c == 'n' && in.get() == 'u' && in.get() == 'l' && in.get() == 'l') {
                out = null;
            } else if (c == '-' || (c >= '0' && c <= '9')) {
                StringBuilder sb = new StringBuilder();
                sb.append(c);
                while (in.hasRemaining()) {
                    if ((c=in.get()) == '.' || c == 'e' || c == 'E' || (c >= '0' && c <= '9')) {
                        sb.append(c);
                    } else {
                        in.position(in.position() - 1);
                        break;
                    }
                }
                String s = sb.toString();
                try {
                    Long l = Long.parseLong(s);
                    if (l.longValue() == l.intValue()) {        // This can't be done with a ternary due to unboxing confusion
                        out = Integer.valueOf(l.intValue());
                    } else {
                        out = l;
                    }
                } catch (Exception e) {
                    try {
                        out = Double.parseDouble(s);
                    } catch (Exception e2) {
                        throw new UnsupportedOperationException("invalid number: " + s);
                    }
                }
            } else {
                throw new UnsupportedOperationException("invalid " + (c >= ' ' && c < 0x80 ? "'" + ((char)c) + "'" : "U+" + Integer.toHexString(c)));
            }
            return out;
        } catch (BufferUnderflowException e) {
            throw (IllegalArgumentException)new IllegalArgumentException("Parse failed: unexpected EOF").initCause(e);
        } catch (ClassCastException e) {
            in.position(tell);
            throw new IllegalArgumentException("Parse failed at " + in.position() + ": expected string");
        } catch (UnsupportedOperationException e) {
            in.position(tell);
            throw new IllegalArgumentException("Parse failed at " + in.position() + ": " + e.getMessage());
        }
    }

    /**
     * The callback which must be populated to complete an OAuth2 transaction.
     * This callback is created when the <code>access_token</code> is required and
     * cannot be created by renewal.
     */
    public static class Callback {

        private final OAuth2 auth;
        private final String redirecturi;
        private final String uri;
        private final Map<String,String> props;
        private String code;

        /**
         * Create a new OAuth2Callback
         * @param auth the OAuth2 object
         * @param redirecturi the initial "redirect_uri" value
         * @param uri the initial "uri" value
         * @param props a map of any additional properties
         */
        public Callback(OAuth2 auth, String redirecturi, String uri, Map<String,String> props) {
            this.auth = auth;
            this.redirecturi = redirecturi;
            this.uri = uri;
            this.props = props;
        }

        /**
         * Return the OAuth2 object that created this callback
         */
        public OAuth2 getOAuth2() {
            return auth;
        }

        /**
         * Return the <code>redirect_uri</code>
         */
        public String getRedirectURI() {
            return redirecturi;
        }

        /**
         * Return the <code>auth_uri</code> which the CallbackHandler must load for authorization
         */
        public String getAuthURI() {
            return uri;
        }

        /**
         * Return a map of properties which apply to the session. The list of
         * keys is undefined but may include <code>scope</code>
         */
        public Map<String,String> getProperties() {
            return props;
        }

        /**
         * Return the code set by the {@link javax.security.auth.callback.CallbackHandler}
         */
        public String getCode() {
            return code;
        }

        /**
         * Set the code that was given by the authorization process.
         * This method must be called by the {@link javax.security.auth.callback.CallbackHandler}
         */
        public void setCode(String code) {
            this.code = code;
        }

    }

    public static interface CallbackHandler {
        /**
         * Called by {@link OAuth2#configure} to notify the CallbackHandler it is in use
         */
        public void configure(OAuth2 oauth2, Map<String,String> properties);

        /**
         * Initialize a callback, which will require the user to open a web-browser to continue OAuth2 authorization
         */
        public void callback(Callback callback) throws IOException;

        /**
         * Notified after a callback completes or the configuration is updated for any reason.
         * Can be overridden to save the configuration immediately
         * @see OAuth2#isUpdated
         */
        public void configurationUpdated(Map<String,String> properties);
    }

    /**
     * An implementation of {@link CallbackHandler} that can support {@link OAuth2Callback}
     * It uses the <Code>com.sun.net.httpserver</code> package to create a local webserver
     * and then directs the user to that URL to begin the authentication process.
     */
    public static class SimpleCallbackHandler implements CallbackHandler {

        private OAuth2 oauth2;
        private HttpServer server;
        private SSLContext ssl;
        private URI redirectURL, initialURL;
        private String initialPath, finalURL;
        private int port;
        private volatile int count;
        private long timeout = 5 * 60 * 1000;

        /**
         * Create a SimpleCallbackHandler
         */
        public SimpleCallbackHandler() {
            setFinalURL(null);
        }

        /**
         * Set the local URL of the redirect_uri. Normally this is taken from the <code>redirect_uri</code> passed in
         * to the OAuth2 object, but this method can set a different URL, port etc. to listen on locally if that URL
         * references a public proxy.
         */
        public void setRedirectURL(String url) {
            try {
                this.redirectURL = url == null ? null : new URI(url);
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URL \"" + url + "\"", e);
            }
        }

        /**
         * Set the base path for the initial URL given to the user to begin authorization.
         */
        public void setInitialURL(String url, String localPath) {
            try {
                this.initialURL = url == null ? null : new URI(url);
                if (initialURL != null && localPath == null) {
                    localPath = initialURL.getPath();
                }
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException("Invalid URL \"" + url + "\"", e);
            }
            if (localPath != null) {
                if (!localPath.startsWith("/")) {
                    localPath = "/" + localPath;
                }
                if (localPath.contains("?") || localPath.contains("#")) {
                    throw new IllegalStateException("SimpleCallback: invalid localPath \"" + localPath + "\"");
                }
            }
            this.initialPath = localPath;
        }

        public void setFinalURL(String url) {
            this.finalURL = url == null ? "about:blank" : url;
        }

        public void setSSLContext(SSLContext ssl) {
            this.ssl = ssl;
        }

        public void setSSLContext(KeyStore keystore, char[] password) throws NoSuchAlgorithmException, KeyStoreException, KeyManagementException, UnrecoverableKeyException {
            if (keystore == null) {
                ssl = null;
            } else {
                ssl = SSLContext.getInstance("TLS");
                KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                kmf.init(keystore, password);
                TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                tmf.init(keystore);
                ssl.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            }
        }

        @Override public void configurationUpdated(Map<String,String> props) {
            // noop
        }

        @Override public void configure(OAuth2 oauth2, Map<String,String> props) {
            if (this.oauth2 != null) {
                throw new IllegalStateException("Already configured");
            }
            this.oauth2 = oauth2;
            if (redirectURL == null) {
                setRedirectURL(props.get("redirect_uri"));
                if (redirectURL == null) {
                    throw new IllegalStateException("redirect_uri is required to configure SimpleCallback");
                }
            }
            String redirectPath = redirectURL.getPath();
            if (redirectPath == null || !redirectPath.startsWith("/") || redirectPath.contains("?") || redirectPath.contains("#")) {
                throw new IllegalStateException("SimpleCallback: invalid redirectPath \"" + redirectPath + "\"");
            }
            if (initialPath == null) {
                initialPath = redirectPath.equals("/authorize") ? "/" : "/authorize";
            }
            if (initialPath == null || !initialPath.startsWith("/") || initialPath.contains("?") || initialPath.contains("#")) {
                throw new IllegalStateException("SimpleCallback: invalid initialPath \"" + initialPath + "\"");
            }
            if (initialPath.equals(redirectPath)) {
                throw new IllegalStateException("SimpleCallback: invalid initialPath \"" + initialPath + "\" (identical to redirectPath)");
            }
            if (initialURL == null) {
                String s = redirectURL.getScheme() + "://" + redirectURL.getHost() + ":" + redirectURL.getPort() + initialPath;
                try {
                    initialURL = new URI(s);
                } catch (URISyntaxException e) {
                    throw new IllegalArgumentException("Invalid URL \"" + s + "\"", e);
                }
            }
        }

        /**
         * Set the timeout to wait for a response
         * @param timeout the timeout in milliseconds
         */
        public synchronized void setTimeout(long timeout) {
            this.timeout = timeout;
        }

        /**
         * Get the timeout as set by {@link #setTimeout}
         * @return the timeout in milliseconds
         */
        public synchronized long getTimeout() {
            return timeout;
        }

        /**
         * Notify the user that they must visit the specified URL to start an OAuth2 transaction
         * By default this prints a message to System.out
         * @param uri the URL to visit
         */
        protected void notifyCallback(String url) {
            System.out.println("Go to " + url);
        }

        protected void log(Exception e) {
            e.printStackTrace();
        }

        /**
         * Start the webserver
         */
        protected void start() throws IOException {
            final int port = redirectURL.getPort();
            if (ssl != null) {
                server = HttpsServer.create(new InetSocketAddress(port), 0);
                ((HttpsServer)server).setHttpsConfigurator(new HttpsConfigurator(ssl) {
                    public void configure(HttpsParameters params) {
                        params.setNeedClientAuth(false);
                        params.setSSLParameters(ssl.getDefaultSSLParameters());
                        //params.setCipherSuites(ssl.getEnabledCipherSuites());
                        //params.setProtocols(ssl.getEnabledProtocols());
                    }
                });
            } else {
                server = HttpServer.create(new InetSocketAddress(port), 0);
            }
            Thread thread = new Thread() {
                public void run() {
                    server.start();
                }
            };
            thread.setDaemon(true);
            thread.setName("BFO-Publisher-OAuth2-SimpleOAuth2Callback");
            thread.start();
        }

        /**
         * Stop the webserver
         */
        protected void stop() {
            server.stop(1);
        }

        @Override public void callback(Callback callback) throws IOException {
            String uri = callback.getAuthURI();
            Map<String,String> props = callback.getProperties();
            OAuth2 oauth = callback.getOAuth2();

            synchronized(this) {
                if (count++ == 0) {
                    start();
                }
            }
            final HttpContext[] ctx = new HttpContext[2];
            System.out.println("Listening on "+initialPath);
            ctx[0] = server.createContext(initialPath, new HttpHandler() {
                @Override public void handle(HttpExchange t) throws IOException {
                    try {
                        if (oauth2.debug) debug("web-request: " + uri);
                        t.getResponseHeaders().add("Location", uri);
                        t.sendResponseHeaders(302, 0);
                        t.close();
                    } catch (Exception e) {
                        log(e);
                    }
                }
            });
            System.out.println("Listening on "+redirectURL.getPath());
            ctx[1] = server.createContext(redirectURL.getPath(), new HttpHandler() {
                @Override public void handle(HttpExchange t) throws IOException {
                    try {
                        if (oauth2.debug) debug("web-response: " + t.getRequestURI());
                        Map<String,List<String>> m = parseURLParameters(t.getRequestURI().getQuery());
                        if (props.containsKey("state")) {
                            if (!(m.containsKey("state") && m.get("state").size() == 1 && props.get("state").equals(m.get("state").get(0)))) {
                                throw new IOException("state mismatch");
                            }
                        }
                        t.getResponseHeaders().add("Location", finalURL);
                        t.sendResponseHeaders(302, 0);
                        t.close();
                        server.removeContext(ctx[0]);
                        server.removeContext(ctx[1]);
                        synchronized(SimpleCallbackHandler.this) {
                            if (--count == 0) {
                                stop();
                            }
                        }
                        callback.setCode(m.get("code").get(0));
                    } catch (IOException e) {
                        log(e);
                    } catch (RuntimeException e) {
                        log(e);
                    } finally {
                        synchronized(callback) {
                            try {
                                callback.notifyAll();
                            } catch (Exception e) {}
                        }
                    }
                }
            });
            notifyCallback(initialURL.toString());
            synchronized(callback) {
                try {
                    callback.wait(getTimeout());
                } catch (InterruptedException e) {}
            }
        }
    }

}
