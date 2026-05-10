package com.example.mob_sec_proj;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class UrlResolver {

    public interface Callback {
        void onResolved(String finalUrl, List<String> hops);
    }

    private static final int MAX_REDIRECTS = 10;

    public static void resolve(String startUrl, Callback callback) {

        OkHttpClient client = new OkHttpClient.Builder()
                .followRedirects(false)
                .followSslRedirects(false)
                .build();

        new Thread(() -> {

            List<String> hops = new ArrayList<>();
            Set<String> visited = new HashSet<>(); // NEW: track visited URLs

            String currentUrl = startUrl;

            try {

                for (int i = 0; i < MAX_REDIRECTS; i++) {

                    // loop
                    if (visited.contains(currentUrl)) {
                        hops.add(currentUrl);
                        break;
                    }
                    visited.add(currentUrl);

                    Request request = new Request.Builder()
                            .url(currentUrl)
                            // spoof browser agent
                            .header("User-Agent",
                                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                                            "AppleWebKit/537.36 (KHTML, like Gecko) " +
                                            "Chrome/120.0.0.0 Safari/537.36")
                            .get()
                            .build();

                    try (Response response = client.newCall(request).execute()) {

                        hops.add(currentUrl);

                        int code = response.code();

                        // break at not expected response
                        if (code < 300 || code >= 400) {
                            break;
                        }

                        String location = response.header("Location");

                        if (location == null) {
                            break;
                        }

                        HttpUrl base = HttpUrl.parse(currentUrl);
                        HttpUrl next = base != null
                                ? base.resolve(location)
                                : HttpUrl.parse(location);

                        if (next == null) {
                            break;
                        }

                        currentUrl = next.toString();
                    }
                }

            } catch (Exception e) {
                hops.add(currentUrl);
            }

            String finalUrl = currentUrl;
            callback.onResolved(finalUrl, hops);

        }).start();
    }
}