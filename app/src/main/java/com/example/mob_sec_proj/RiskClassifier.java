package com.example.mob_sec_proj;

public class RiskClassifier {

    // Cert score weights
    private static final int SCORE_CERT_HANDSHAKE_FAILED = 3;
    private static final int SCORE_CERT_EXPIRED          = 2;
    private static final int SCORE_CERT_DOMAIN_MISMATCH  = 2;
    private static final int SCORE_CERT_SELF_SIGNED      = 1;
    private static final int SCORE_CERT_NOT_YET_VALID    = 1;

    public static String classify(
            String googleResult,
            boolean phishTankHit,
            int heuristicScore,
            CertificateAnalyzer.CertResult certResult
    ) {
        int score = 0;

        // Google Safe Browsing
        if (GoogleSafeBrowsing.DANGEROUS.equals(googleResult)) {
            score += 5;
        }

        // PhishTank
        if (phishTankHit) {
            score += 5;
        }

        // Heuristics
        score += heuristicScore;

        // Certificate
        if (certResult != null) {
            if (certResult.valid) {
                if (certResult.expired)       score += SCORE_CERT_EXPIRED;
                if (certResult.notYetValid)   score += SCORE_CERT_NOT_YET_VALID;
                if (certResult.selfSigned)    score += SCORE_CERT_SELF_SIGNED;
                if (!certResult.domainMatch)  score += SCORE_CERT_DOMAIN_MISMATCH;
            } else if (certResult.handshakeFailed) {
                // active TLS failure on an https URL is a meaningful signal
                score += SCORE_CERT_HANDSHAKE_FAILED;
            }

        }

        String label;

        if (score >= 5) {
            label = "MALICIOUS";
        } else if (score >= 2) {
            label = "SUSPICIOUS";
        } else {
            label = "SAFE";
        }

        return label + "|" + score + "|" + heuristicScore;
    }
}