import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class EmployeePayrollSystem {
    private static final Path ACCOUNT_FILE = Path.of(
        System.getProperty("user.home"), ".employee-payroll-system", "account.properties");
    private static final int PASSWORD_ITERATIONS = 210_000;
    private static final int MAX_REQUEST_BYTES = 16_384;
    private static final long SESSION_MILLIS = 8 * 60 * 60 * 1000L;
    private static final long REMEMBER_MILLIS = 30 * 24 * 60 * 60 * 1000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Object ACCOUNT_LOCK = new Object();
    private static final Map<String, Long> SESSIONS = new ConcurrentHashMap<>();
    private static volatile Account account;

    private record Account(String displayName, String username, String salt, String passwordHash) {}

    public static void main(String[] args) throws Exception {
        account = loadAccount();

        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);

        server.createContext("/", EmployeePayrollSystem::handleRequest);
        server.start();
        System.out.println("Employee Payroll System started!");
        System.out.println("Open: http://localhost:" + server.getAddress().getPort());
        System.out.println(account == null
            ? "Create the first account when the setup page opens."
            : "Sign in with your saved account.");
    }

    private static void handleRequest(HttpExchange exchange) {
        try {
            String path = exchange.getRequestURI().getPath();
            String method = exchange.getRequestMethod();

            if (path.equals("/api/setup") && method.equals("POST")) {
                setupAccount(exchange);
                return;
            }
            if (path.equals("/api/login") && method.equals("POST")) {
                login(exchange);
                return;
            }
            if (path.equals("/api/logout") && method.equals("POST")) {
                logout(exchange);
                return;
            }
            if (path.equals("/api/account")) {
                if (!method.equals("GET")) {
                    sendJson(exchange, 405, "{\"error\":\"Method not allowed.\"}");
                } else if (requireSession(exchange)) {
                    sendJson(exchange, 200, "{\"displayName\":" + jsonString(account.displayName())
                        + ",\"username\":" + jsonString(account.username()) + "}");
                }
                return;
            }
            if (path.equals("/api/profile") && method.equals("POST")) {
                updateProfile(exchange);
                return;
            }
            if (path.equals("/api/password") && method.equals("POST")) {
                updatePassword(exchange);
                return;
            }

            if (!method.equals("GET")) {
                sendText(exchange, 405, "Method not allowed");
                return;
            }
            servePage(exchange, path);
        } catch (IllegalArgumentException e) {
            sendError(exchange, 400, errorJson(e.getMessage()));
        } catch (IOException | GeneralSecurityException e) {
            sendError(exchange, 500, "{\"error\":\"The request could not be completed.\"}");
        } finally {
            exchange.close();
        }
    }

    private static void servePage(HttpExchange exchange, String path) throws IOException {
        boolean configured = account != null;
        boolean authenticated = hasSession(exchange);

        if (path.equals("/")) {
            redirect(exchange, !configured ? "/setup.html" : authenticated ? "/dashboard.html" : "/login.html");
            return;
        }
        if (path.equals("/login.html")) {
            if (!configured) {
                redirect(exchange, "/setup.html");
            } else if (authenticated) {
                redirect(exchange, "/dashboard.html");
            } else {
                sendFile(exchange, "login.html");
            }
            return;
        }
        if (path.equals("/setup.html")) {
            if (configured) {
                redirect(exchange, authenticated ? "/dashboard.html" : "/login.html");
            } else {
                sendFile(exchange, "setup.html");
            }
            return;
        }
        if (path.equals("/style.css") || path.equals("/app.js")) {
            sendFile(exchange, path.substring(1));
            return;
        }
        if (!Map.of("/dashboard.html", "dashboard.html", "/employees.html", "employees.html",
            "/payroll.html", "payroll.html", "/reports.html", "reports.html",
            "/settings.html", "settings.html").containsKey(path)) {
            sendText(exchange, 404, "Not found");
            return;
        }
        if (!configured) {
            redirect(exchange, "/setup.html");
            return;
        }
        if (!authenticated) {
            redirect(exchange, "/login.html");
            return;
        }
        sendFile(exchange, path.substring(1));
    }

    private static void setupAccount(HttpExchange exchange) throws IOException, GeneralSecurityException {
        if (account != null) {
            sendJson(exchange, 409, "{\"error\":\"Workspace access is already configured.\"}");
            return;
        }
        Map<String, String> form = readForm(exchange);
        String displayName = required(form, "displayName", "Enter a display name.");
        String username = validateUsername(required(form, "username", "Enter a username."));
        String password = validatePassword(required(form, "password", "Enter a password."));

        synchronized (ACCOUNT_LOCK) {
            if (account != null || Files.exists(ACCOUNT_FILE)) {
                account = loadAccount();
                sendJson(exchange, 409, "{\"error\":\"Workspace access is already configured.\"}");
                return;
            }
            Account created = createAccount(displayName, username, password);
            saveAccount(created);
            account = created;
        }
        createSession(exchange, false);
        sendJson(exchange, 201, "{\"redirect\":\"/dashboard.html\"}");
    }

    private static void login(HttpExchange exchange) throws IOException, GeneralSecurityException {
        if (account == null) {
            sendJson(exchange, 409, "{\"error\":\"setup_required\",\"redirect\":\"/setup.html\"}");
            return;
        }
        Map<String, String> form = readForm(exchange);
        String username = form.getOrDefault("username", "").trim();
        String password = form.getOrDefault("password", "");
        if (!account.username().equals(username) || !verifyPassword(password, account)) {
            sendJson(exchange, 401, "{\"error\":\"Username or password is incorrect.\"}");
            return;
        }
        createSession(exchange, "on".equals(form.get("remember")));
        sendJson(exchange, 200, "{\"redirect\":\"/dashboard.html\"}");
    }

    private static void updateProfile(HttpExchange exchange) throws IOException, GeneralSecurityException {
        if (!requireSession(exchange)) return;
        Map<String, String> form = readForm(exchange);
        String currentPassword = form.getOrDefault("currentPassword", "");
        if (!verifyPassword(currentPassword, account)) {
            sendJson(exchange, 401, "{\"error\":\"Current password is incorrect.\"}");
            return;
        }
        String displayName = required(form, "displayName", "Enter a display name.");
        String username = validateUsername(required(form, "username", "Enter a username."));
        Account updated = new Account(displayName, username, account.salt(), account.passwordHash());
        synchronized (ACCOUNT_LOCK) {
            saveAccount(updated);
            account = updated;
        }
        sendJson(exchange, 200, "{\"message\":\"Account details updated.\"}");
    }

    private static void updatePassword(HttpExchange exchange) throws IOException, GeneralSecurityException {
        if (!requireSession(exchange)) return;
        Map<String, String> form = readForm(exchange);
        if (!verifyPassword(form.getOrDefault("currentPassword", ""), account)) {
            sendJson(exchange, 401, "{\"error\":\"Current password is incorrect.\"}");
            return;
        }
        String password = validatePassword(required(form, "newPassword", "Enter a new password."));
        if (!password.equals(form.get("confirmPassword"))) {
            sendJson(exchange, 400, "{\"error\":\"New passwords do not match.\"}");
            return;
        }
        Account updated = createAccount(account.displayName(), account.username(), password);
        synchronized (ACCOUNT_LOCK) {
            saveAccount(updated);
            account = updated;
            SESSIONS.clear();
        }
        createSession(exchange, false);
        sendJson(exchange, 200, "{\"message\":\"Password updated.\"}");
    }

    private static void logout(HttpExchange exchange) throws IOException {
        String token = sessionToken(exchange);
        if (token != null) SESSIONS.remove(token);
        exchange.getResponseHeaders().add("Set-Cookie",
            "PAYFLOW_SESSION=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
        sendJson(exchange, 200, "{\"redirect\":\"/login.html\"}");
    }

    private static boolean requireSession(HttpExchange exchange) throws IOException {
        if (account != null && hasSession(exchange)) return true;
        sendJson(exchange, 401, "{\"error\":\"Sign in to continue.\",\"redirect\":\"/login.html\"}");
        return false;
    }

    private static boolean hasSession(HttpExchange exchange) {
        String token = sessionToken(exchange);
        if (token == null) return false;
        Long expiry = SESSIONS.get(token);
        if (expiry == null) return false;
        if (expiry < System.currentTimeMillis()) {
            SESSIONS.remove(token);
            return false;
        }
        return true;
    }

    private static String sessionToken(HttpExchange exchange) {
        String cookie = exchange.getRequestHeaders().getFirst("Cookie");
        if (cookie == null) return null;
        for (String item : cookie.split(";")) {
            String[] parts = item.trim().split("=", 2);
            if (parts.length == 2 && parts[0].equals("PAYFLOW_SESSION")) return parts[1];
        }
        return null;
    }

    private static void createSession(HttpExchange exchange, boolean remember) {
        byte[] tokenBytes = new byte[32];
        RANDOM.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        long duration = remember ? REMEMBER_MILLIS : SESSION_MILLIS;
        SESSIONS.put(token, System.currentTimeMillis() + duration);
        exchange.getResponseHeaders().add("Set-Cookie", "PAYFLOW_SESSION=" + token
            + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + duration / 1000);
    }

    private static Account createAccount(String displayName, String username, String password)
        throws GeneralSecurityException {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return new Account(displayName, username, Base64.getEncoder().encodeToString(salt),
            hashPassword(password, salt));
    }

    private static Account loadAccount() throws IOException {
        if (!Files.exists(ACCOUNT_FILE)) return null;
        Properties properties = new Properties();
        try (var input = Files.newInputStream(ACCOUNT_FILE)) {
            properties.load(input);
        }
        return new Account(properties.getProperty("displayName", ""),
            properties.getProperty("username", ""), properties.getProperty("salt", ""),
            properties.getProperty("passwordHash", ""));
    }

    private static void saveAccount(Account value) throws IOException {
        Path parent = ACCOUNT_FILE.getParent();
        Files.createDirectories(parent);
        Properties properties = new Properties();
        properties.setProperty("displayName", value.displayName());
        properties.setProperty("username", value.username());
        properties.setProperty("salt", value.salt());
        properties.setProperty("passwordHash", value.passwordHash());
        Path temporary = Files.createTempFile(parent, "account-", ".tmp");
        try {
            try (OutputStream output = Files.newOutputStream(temporary)) {
                properties.store(output, "Payflow local account");
            }
            try {
                Files.move(temporary, ACCOUNT_FILE, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temporary, ACCOUNT_FILE, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static boolean verifyPassword(String password, Account value) throws GeneralSecurityException {
        if (password.isEmpty()) return false;
        byte[] salt = Base64.getDecoder().decode(value.salt());
        byte[] expected = Base64.getDecoder().decode(value.passwordHash());
        byte[] actual = Base64.getDecoder().decode(hashPassword(password, salt));
        return MessageDigest.isEqual(expected, actual);
    }

    private static String hashPassword(String password, byte[] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PASSWORD_ITERATIONS, 256);
        try {
            byte[] hash = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } finally {
            ((PBEKeySpec) spec).clearPassword();
        }
    }

    private static String validateUsername(String username) {
        String normalized = username.trim();
        if (normalized.length() < 3 || normalized.length() > 40
            || normalized.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Username must be 3–40 characters.");
        }
        return normalized;
    }

    private static String validatePassword(String password) {
        if (password.length() < 10 || password.length() > 256) {
            throw new IllegalArgumentException("Password must be between 10 and 256 characters.");
        }
        return password;
    }

    private static String required(Map<String, String> form, String key, String message) {
        String value = form.getOrDefault(key, "").trim();
        if (value.isEmpty()) throw new IllegalArgumentException(message);
        if (value.length() > 100) throw new IllegalArgumentException("Input is too long.");
        return value;
    }

    private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
        byte[] bytes = exchange.getRequestBody().readNBytes(MAX_REQUEST_BYTES + 1);
        if (bytes.length > MAX_REQUEST_BYTES) throw new IllegalArgumentException("Request is too large.");
        Map<String, String> values = new HashMap<>();
        String body = new String(bytes, StandardCharsets.UTF_8);
        for (String pair : body.split("&")) {
            if (pair.isEmpty()) continue;
            String[] parts = pair.split("=", 2);
            String key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8);
            String value = parts.length == 2 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "";
            values.put(key, value);
        }
        return values;
    }

    private static void sendFile(HttpExchange exchange, String fileName) throws IOException {
        Path file = Path.of("web", fileName);
        if (!Files.isRegularFile(file)) {
            sendText(exchange, 404, "Not found");
            return;
        }
        byte[] content = Files.readAllBytes(file);
        String contentType = fileName.endsWith(".css") ? "text/css; charset=UTF-8"
            : fileName.endsWith(".js") ? "text/javascript; charset=UTF-8"
            : "text/html; charset=UTF-8";
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, content.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(content);
        }
    }

    private static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().set("Location", location);
        exchange.sendResponseHeaders(303, -1);
    }

    private static void sendText(HttpExchange exchange, int status, String text) throws IOException {
        byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=UTF-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=UTF-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    private static void sendError(HttpExchange exchange, int status, String json) {
        try {
            sendJson(exchange, status, json);
        } catch (IOException ignored) {
        }
    }

    private static String errorJson(String message) {
        return "{\"error\":" + jsonString(message == null ? "Invalid request." : message) + "}";
    }

    private static String jsonString(String value) {
        StringBuilder result = new StringBuilder("\"");
        for (char character : value.toCharArray()) {
            switch (character) {
                case '"' -> result.append("\\\"");
                case '\\' -> result.append("\\\\");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (character < 0x20) result.append(String.format("\\u%04x", (int) character));
                    else result.append(character);
                }
            }
        }
        return result.append('"').toString();
    }
}