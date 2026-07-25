package com.morokss.android;

import android.util.Base64;

import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class Profile {
    final String rawJson;
    final String secret;
    final List<String> endpoints;
    final String shadowsocksMethod;
    final String shadowsocksPassword;

    private Profile(
            String rawJson,
            String secret,
            List<String> endpoints,
            String shadowsocksMethod,
            String shadowsocksPassword
    ) {
        this.rawJson = rawJson;
        this.secret = secret;
        this.endpoints = endpoints;
        this.shadowsocksMethod = shadowsocksMethod;
        this.shadowsocksPassword = shadowsocksPassword;
    }

    static Profile parse(String rawJson) throws JSONException {
        JSONObject root = new JSONObject(rawJson);
        String hostname = required(root, "hostname");
        String secret = required(root, "morokss_secret");
        if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new JSONException("morokss_secret must contain at least 32 UTF-8 bytes");
        }

        Set<String> uniqueEndpoints = new LinkedHashSet<>();
        addEndpoint(uniqueEndpoints, root.optString("endpoint_ipv6", ""), hostname);
        addEndpoint(uniqueEndpoints, root.optString("endpoint_ipv4", ""), hostname);
        addEndpoint(uniqueEndpoints, root.optString("endpoint", ""), hostname);
        if (uniqueEndpoints.isEmpty()) {
            throw new JSONException("profile has no MorokSS endpoints");
        }

        JSONObject shadowsocks = root.optJSONObject("shadowsocks");
        if (shadowsocks == null) {
            throw new JSONException("profile has no shadowsocks section");
        }
        String method = required(shadowsocks, "method");
        String password = required(shadowsocks, "password");

        return new Profile(
                rawJson,
                secret,
                new ArrayList<>(uniqueEndpoints),
                method,
                password
        );
    }

    String shadowsocksUri() {
        String credentials = shadowsocksMethod + ":" + shadowsocksPassword;
        String encoded = Base64.encodeToString(
                credentials.getBytes(StandardCharsets.UTF_8),
                Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING
        );
        return "ss://" + encoded + "@127.0.0.1:8389#MorokSS%20Android";
    }

    private static String required(JSONObject object, String name) throws JSONException {
        String value = object.optString(name, "").trim();
        if (value.isEmpty()) {
            throw new JSONException("missing " + name);
        }
        return value;
    }

    private static void addEndpoint(Set<String> endpoints, String raw, String hostname) {
        String value = raw == null ? "" : raw.trim();
        if (value.isEmpty()) {
            return;
        }
        endpoints.add(value.contains(",") ? value : value + "," + hostname);
    }
}
