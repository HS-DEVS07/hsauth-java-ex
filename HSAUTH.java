package com.hsauth;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Official HS DEVS AUTH Java Client SDK
 * Zero external libraries required. Pure Java SE 8+.
 */
public class HSAUTH {

    public String name;
    public String ownerid;
    public String version;
    public String apiUrl;
    public String sessionid;
    public boolean initialized = false;

    public Map<String, String> userData = new HashMap<>();
    public Map<String, String> appData = new HashMap<>();
    public Map<String, String> lastResponse = new HashMap<>();

    public HSAUTH(String name, String ownerid, String version, String apiUrl) {
        this.name = name;
        this.ownerid = ownerid;
        this.version = (version == null || version.isEmpty()) ? "1.0" : version;
        this.apiUrl = (apiUrl == null || apiUrl.isEmpty()) ? "https://hsauth.mujahid.xyz/api/1.3/" : apiUrl;
        if (!this.apiUrl.endsWith("/")) this.apiUrl += "/";
    }

    public HSAUTH(String name, String ownerid, String version) {
        this(name, ownerid, version, "https://hsauth.mujahid.xyz/api/1.3/");
    }

    public static String getHWID() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                Process process = Runtime.getRuntime().exec("reg query HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid");
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("MachineGuid")) {
                        String[] parts = line.split("\\s+");
                        return parts[parts.length - 1];
                    }
                }
            }
        } catch (Exception ignored) {}

        String fallback = System.getProperty("user.name") + System.getProperty("os.name") + Runtime.getRuntime().availableProcessors();
        return Integer.toHexString(fallback.hashCode());
    }

    private String req(Map<String, String> data) {
        data.put("name", this.name);
        data.put("ownerid", this.ownerid);

        try {
            StringBuilder postData = new StringBuilder();
            for (Map.Entry<String, String> param : data.entrySet()) {
                if (postData.length() != 0) postData.append('&');
                postData.append(URLEncoder.encode(param.getKey(), "UTF-8"));
                postData.append('=');
                postData.append(URLEncoder.encode(param.getValue() != null ? param.getValue() : "", "UTF-8"));
            }

            URL url = new URL(this.apiUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("User-Agent", "HSAuth-Java/1.0");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData.toString().getBytes(StandardCharsets.UTF_8));
            }

            InputStream is = (conn.getResponseCode() >= 400) ? conn.getErrorStream() : conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        } catch (Exception e) {
            return "{\"success\":false,\"message\":\"" + e.getMessage() + "\"}";
        }
    }

    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\":\"";
        int idx = json.indexOf(search);
        if (idx == -1) return "";
        int start = idx + search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return "";
        return json.substring(start, end);
    }

    public boolean init() {
        Map<String, String> params = new HashMap<>();
        params.put("type", "init");
        params.put("ver", this.version);

        String raw = req(params);
        boolean success = raw.contains("\"success\":true");
        if (success) {
            this.sessionid = extractJsonValue(raw, "sessionid");
            this.appData.put("version", extractJsonValue(raw, "version"));
            this.initialized = true;
        }
        return success;
    }

    public boolean login(String username, String password) {
        Map<String, String> params = new HashMap<>();
        params.put("type", "login");
        params.put("username", username);
        params.put("pass", password);
        params.put("hwid", getHWID());
        params.put("sessionid", this.sessionid);

        String raw = req(params);
        boolean success = raw.contains("\"success\":true");
        if (success) {
            this.userData.put("username", extractJsonValue(raw, "username"));
            this.userData.put("hwid", extractJsonValue(raw, "hwid"));
            String sess = extractJsonValue(raw, "sessionid");
            if (!sess.isEmpty()) this.sessionid = sess;
        }
        return success;
    }

    public boolean register(String username, String password, String key) {
        Map<String, String> params = new HashMap<>();
        params.put("type", "register");
        params.put("username", username);
        params.put("pass", password);
        params.put("key", key);
        params.put("hwid", getHWID());
        params.put("sessionid", this.sessionid);

        String raw = req(params);
        return raw.contains("\"success\":true");
    }

    public boolean license(String key) {
        Map<String, String> params = new HashMap<>();
        params.put("type", "license");
        params.put("key", key);
        params.put("hwid", getHWID());
        params.put("sessionid", this.sessionid);

        String raw = req(params);
        boolean success = raw.contains("\"success\":true");
        if (success) {
            this.userData.put("username", extractJsonValue(raw, "username"));
            this.userData.put("hwid", extractJsonValue(raw, "hwid"));
            String sess = extractJsonValue(raw, "sessionid");
            if (!sess.isEmpty()) this.sessionid = sess;
        }
        return success;
    }

    public String var(String varid) {
        Map<String, String> params = new HashMap<>();
        params.put("type", "var");
        params.put("varid", varid);
        params.put("sessionid", this.sessionid);
        String raw = req(params);
        return extractJsonValue(raw, "message");
    }

    public void log(String message) {
        Map<String, String> params = new HashMap<>();
        params.put("type", "log");
        params.put("message", message);
        params.put("sessionid", this.sessionid);
        req(params);
    }
}
