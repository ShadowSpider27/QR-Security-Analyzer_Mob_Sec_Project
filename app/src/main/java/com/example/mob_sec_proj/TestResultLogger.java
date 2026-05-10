package com.example.mob_sec_proj;

import android.util.Log;

public class TestResultLogger {

    private static final String TAG = "QR_TEST_RESULT";

    public static void logResult(
            String originalUrl,
            String resolvedUrl,
            String googleResult,
            boolean PhishTankHit,
            int heuristicScore,
            String warnings,
            String finalRisk
    ) {
        Log.d(TAG,
                "Original URL: " + originalUrl +
                        " | Resolved URL: " + resolvedUrl +
                        " | Google Safe Browsing: " + googleResult +
                        " | PhishTank: " + PhishTankHit +
                        " | Heuristic Score: " + heuristicScore +
                        " | Warnings: " + warnings +
                        " | Final Decision: " + finalRisk
        );
    }
}