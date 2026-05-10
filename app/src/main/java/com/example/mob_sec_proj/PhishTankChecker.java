package com.example.mob_sec_proj;

import androidx.annotation.NonNull;

import org.json.JSONObject;

import java.io.IOException;

import java.util.concurrent.TimeUnit;

import okhttp3.*;

public class PhishTankChecker {

    private static final String API_URL =
            "https://checkurl.phishtank.com/checkurl/";

    private static final int TIMEOUT_SECONDS = 10;

    private static final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build();

    public enum PhishCheckResult {
        PHISHING,
        SUSPICIOUS,
        SAFE_OR_UNKNOWN,
        TIMEOUT,
        ERROR
    }

    public interface PhishCallback {
        void onResult(PhishCheckResult result);
    }

    public static void checkUrl(String urlToCheck, PhishCallback callback) {

        if (urlToCheck == null || urlToCheck.trim().isEmpty()) {
            callback.onResult(PhishCheckResult.ERROR);
            return;
        }

        RequestBody body = new FormBody.Builder()
                .add("url", urlToCheck)
                .add("format", "json")
                .build();

        Request request = new Request.Builder()
                .url(API_URL)
                .header("User-Agent", "phishtank/mobsec-project")
                .post(body)
                .build();

        client.newCall(request).enqueue(new Callback() {

            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                if (e instanceof java.net.SocketTimeoutException) {
                    callback.onResult(PhishCheckResult.TIMEOUT);
                } else {
                    callback.onResult(PhishCheckResult.ERROR);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {

                try {
                    if (!response.isSuccessful() || response.body() == null) {
                        callback.onResult(PhishCheckResult.ERROR);
                        return;
                    }

                    String body = response.body().string();

                    JSONObject json = new JSONObject(body);
                    JSONObject results = json.getJSONObject("results");

                    boolean valid = results.optBoolean("valid", false);
                    boolean inDatabase = results.optBoolean("in_database", false);
                    boolean verified = results.optBoolean("verified", false);

                    //
                    if (valid) {
                        callback.onResult(PhishCheckResult.PHISHING);
                    } else if (inDatabase && !verified) {
                        callback.onResult(PhishCheckResult.SUSPICIOUS);
                    } else {
                        callback.onResult(PhishCheckResult.SAFE_OR_UNKNOWN);
                    }

                } catch (Exception e) {
                    callback.onResult(PhishCheckResult.ERROR);
                } finally {
                    response.close();
                }
            }
        });
    }
}