package com.example.mob_sec_proj;

import java.util.ArrayList;
import java.util.LinkedHashMap;

public class HeuristicAnalyzer {

    // weights
    private static final int SCORE_HTTP = 1;
    private static final int SCORE_SUSPICIOUS_PROTOCOL = 1;
    private static final int SCORE_SHORTENER = 1;
    private static final int SCORE_IP_ADDRESS = 2;
    private static final int SCORE_KEYWORD = 1;
    private static final int SCORE_TOO_MANY_REDIRECTS = 2;
    private static final int REDIRECT_LIMIT = 5;

    // =========================
    // WARNINGS WITH SCORES
    // =========================
    public static ArrayList<String[]> getWarningsWithScores(String url) {

        ArrayList<String[]> warnings = new ArrayList<>();

        if (url == null || url.trim().isEmpty()) {
            warnings.add(new String[]{"URL is empty", "0"});
            return warnings;
        }

        String lower = url.toLowerCase().trim();

        if (lower.startsWith("http://")) {
            warnings.add(new String[]{"Uses HTTP instead of HTTPS", String.valueOf(SCORE_HTTP)});
        }

        if (lower.contains("ftp://") ||
                lower.contains("file://") ||
                lower.contains("javascript:")) {
            warnings.add(new String[]{"Uses a suspicious or uncommon protocol", String.valueOf(SCORE_SUSPICIOUS_PROTOCOL)});
        }

        if (lower.contains("bit.ly/") ||
                lower.contains("tinyurl.com/") ||
                lower.contains("t.co/")) {
            warnings.add(new String[]{"Uses a shortened URL", String.valueOf(SCORE_SHORTENER)});
        }

        if (lower.matches(".*://\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            warnings.add(new String[]{"Uses an IP address instead of a normal domain", String.valueOf(SCORE_IP_ADDRESS)});
        }

        if (lower.contains("login")) {
            warnings.add(new String[]{"Contains login keyword", String.valueOf(SCORE_KEYWORD)});
        }

        if (lower.contains("verify")) {
            warnings.add(new String[]{"Contains verify keyword", String.valueOf(SCORE_KEYWORD)});
        }

        if (lower.contains("password")) {
            warnings.add(new String[]{"Contains password keyword", String.valueOf(SCORE_KEYWORD)});
        }

        if (lower.contains("account")) {
            warnings.add(new String[]{"Contains account keyword", String.valueOf(SCORE_KEYWORD)});
        }

        if (lower.contains("urgent")) {
            warnings.add(new String[]{"Contains urgent keyword", String.valueOf(SCORE_KEYWORD)});
        }
        if (lower.contains("redirect")) {
            warnings.add(new String[]{"Contains redirect keyword", String.valueOf(SCORE_KEYWORD)});
        }
        if (warnings.isEmpty()) {
            warnings.add(new String[]{"No suspicious indicators", "0"});
        }

        return warnings;
    }

    // =========================
    // HOP BREAKDOWN (WITH SCORES)
    // =========================
    public static LinkedHashMap<String, ArrayList<String[]>> getHopBreakdown(ArrayList<String> hops) {

        LinkedHashMap<String, ArrayList<String[]>> result = new LinkedHashMap<>();

        if (hops == null || hops.isEmpty()) {
            ArrayList<String[]> empty = new ArrayList<>();
            empty.add(new String[]{"No redirect data available", "0"});
            result.put("NO_HOPS", empty);
            return result;
        }

        for (int i = 0; i < hops.size(); i++) {
            String hop = hops.get(i);
            String key = "Hop " + (i + 1) + ": " + hop;

            ArrayList<String[]> warnings = getWarningsWithScores(hop);
            result.put(key, warnings);
        }

        return result;
    }

    // =========================
    // SINGLE URL SCORE
    // =========================
    public static int getScore(String url) {

        if (url == null || url.trim().isEmpty()) return 0;

        int score = 0;
        String lower = url.toLowerCase().trim();

        if (lower.startsWith("http://")) {
            score += SCORE_HTTP;
        }

        if (lower.contains("ftp://") ||
                lower.contains("file://") ||
                lower.contains("javascript:")) {
            score += SCORE_SUSPICIOUS_PROTOCOL;
        }

        if (lower.contains("bit.ly/") ||
                lower.contains("tinyurl.com/") ||
                lower.contains("t.co/")) {
            score += SCORE_SHORTENER;
        }

        if (lower.matches(".*://\\d+\\.\\d+\\.\\d+\\.\\d+.*")) {
            score += SCORE_IP_ADDRESS;
        }

        if (lower.contains("login") ||
                lower.contains("verify") ||
                lower.contains("password") ||
                lower.contains("account") ||
                lower.contains("urgent")||
                lower.contains("redirect")){
            score += SCORE_KEYWORD;
        }

        return score;
    }

    // =========================
    // TOTAL SCORE (ALL HOPS)
    // =========================
    public static int getScoreFromHops(ArrayList<String> hops) {

        if (hops == null || hops.isEmpty()) return 0;

        int total = 0;

        for (String hop : hops) {
            total += getScore(hop);
        }

        // redirects
        if (hops.size() > REDIRECT_LIMIT) {
            total += SCORE_TOO_MANY_REDIRECTS;
        }

        return total;
    }
}