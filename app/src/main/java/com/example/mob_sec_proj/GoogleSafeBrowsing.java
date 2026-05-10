package com.example.mob_sec_proj;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

public class GoogleSafeBrowsing {

    private static final String API_KEY = "";

    private static final String URL =
            "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + API_KEY;

    private static final int TIMEOUT_SECONDS = 10;

    private static final OkHttpClient client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build();

    // callback
    public interface Callback {
        void onResult(String result);
    }

    // Results
    public static final String SAFE = "SAFE";
    public static final String DANGEROUS = "DANGEROUS";

    public static final String ERROR_NETWORK = "ERROR_NETWORK";
    public static final String ERROR_TIMEOUT = "ERROR_TIMEOUT";
    public static final String ERROR_EMPTY = "ERROR_EMPTY";
    public static final String ERROR_PARSE = "ERROR_PARSE";
    public static final String ERROR_INVALID = "ERROR_INVALID";

    public static void checkUrl(String url, Callback callback) {

        if (url == null || url.trim().isEmpty()) {
            callback.onResult(ERROR_INVALID);
            return;
        }

        try {
            //create json object
            JSONObject json = new JSONObject();

            JSONObject clientJson = new JSONObject();
            clientJson.put("clientId", "qr-app");
            clientJson.put("clientVersion", "1.0");

            JSONObject entry = new JSONObject();
            entry.put("url", url);

            JSONArray threatEntries = new JSONArray();
            threatEntries.put(entry);

            JSONArray threatTypes = new JSONArray();
            threatTypes.put("MALWARE");
            threatTypes.put("SOCIAL_ENGINEERING");
            threatTypes.put("UNWANTED_SOFTWARE");

            JSONArray platformTypes = new JSONArray();
            platformTypes.put("ANY_PLATFORM");

            JSONArray entryTypes = new JSONArray();
            entryTypes.put("URL");

            JSONObject threatInfo = new JSONObject();
            threatInfo.put("threatTypes", threatTypes);
            threatInfo.put("platformTypes", platformTypes);
            threatInfo.put("threatEntryTypes", entryTypes);
            threatInfo.put("threatEntries", threatEntries);

            json.put("client", clientJson);
            json.put("threatInfo", threatInfo);

            // create request

            RequestBody body = RequestBody.create(
                    json.toString(),
                    MediaType.parse("application/json")
            );

            Request request = new Request.Builder()
                    .url(URL)
                    .post(body)
                    .build();

            client.newCall(request).enqueue(new okhttp3.Callback() {

                @Override
                public void onFailure(okhttp3.Call call, IOException e) {
                    if (e instanceof java.net.SocketTimeoutException) {
                        callback.onResult(ERROR_TIMEOUT);
                    } else {
                        callback.onResult(ERROR_NETWORK);
                    }
                }

                @Override
                public void onResponse(okhttp3.Call call, Response response) throws IOException {

                    ResponseBody responseBody = response.body();

                    if (!response.isSuccessful()) {
                        callback.onResult("HTTP_" + response.code());
                        return;
                    }

                    if (responseBody == null) {
                        callback.onResult(ERROR_EMPTY);
                        return;
                    }

                    String res = responseBody.string();

                    try {
                        JSONObject jsonResponse = new JSONObject(res);

                        //
                        if (jsonResponse.has("matches")) {
                            callback.onResult(DANGEROUS);
                        } else {
                            callback.onResult(SAFE);
                        }

                    } catch (Exception e) {
                        callback.onResult(ERROR_PARSE);
                    }
                }
            });

        } catch (Exception e) {
            callback.onResult(ERROR_INVALID);
        }
    }
}