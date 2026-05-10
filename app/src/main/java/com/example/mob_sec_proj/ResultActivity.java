package com.example.mob_sec_proj;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Objects;

public class ResultActivity extends AppCompatActivity {

    TextView original_view, resolved_view, safety_view, total_score_view;
    TextView gsb_view, phish_tank_view, score_view, warnings_view;
    TextView hops_count_view, hops_chain_view;
    TextView cert_status_view, cert_issuer_view, cert_expiry_view;
    TextView cert_self_signed_view, cert_domain_match_view;

    Button results_scan_button, home_return_button, open_browser_button;

    String finalResolvedUrl = null;
    String originalUrl = null;

    @SuppressLint("SetTextI18n")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_result);

        // Bind views
        original_view = findViewById(R.id.txtLink);
        resolved_view = findViewById(R.id.txtResolvedLink);
        safety_view = findViewById(R.id.txtSafety);
        total_score_view = findViewById(R.id.txtTotalScore);

        gsb_view = findViewById(R.id.txtSafeBrowsing);
        phish_tank_view = findViewById(R.id.txtPhishTank);
        score_view = findViewById(R.id.txtScore);
        warnings_view = findViewById(R.id.txtWarnings);

        hops_count_view = findViewById(R.id.txtHopsCount);
        hops_chain_view = findViewById(R.id.txtHopsChain);

        cert_status_view = findViewById(R.id.txtCertStatus);
        cert_issuer_view = findViewById(R.id.txtCertIssuer);
        cert_expiry_view = findViewById(R.id.txtCertExpiry);
        cert_self_signed_view = findViewById(R.id.txtCertSelfSigned);
        cert_domain_match_view = findViewById(R.id.txtCertDomainMatch);

        results_scan_button = findViewById(R.id.btnScanAgain);
        home_return_button = findViewById(R.id.btnHome);
        open_browser_button = findViewById(R.id.btnOpenBrowser);

        String qr = getIntent().getStringExtra("qr");
        originalUrl = qr;
        original_view.setText(qr);

        open_browser_button.setEnabled(false);

        if (qr == null || !(qr.startsWith("http://") || qr.startsWith("https://"))) {
            safety_view.setText(getString(R.string.invalid_url_message));
            safety_view.setTextColor(Color.rgb(255, 140, 0));
            total_score_view.setText("-");

            resolved_view.setText(getString(R.string.not_resolved));
            gsb_view.setText("-");
            phish_tank_view.setText("-");
            score_view.setText("-");
            warnings_view.setText("-");
            hops_count_view.setText("-");
            hops_chain_view.setText("-");
            setCertFields("-", "-", "-", "-", "-");

            setupButtons();
            return;
        }

        // Loading state
        safety_view.setText(getString(R.string.checking));
        safety_view.setTextColor(Color.DKGRAY);

        String loading = getString(R.string.loading);
        gsb_view.setText(loading);
        phish_tank_view.setText(loading);
        score_view.setText(loading);
        warnings_view.setText(loading);
        hops_count_view.setText(loading);
        hops_chain_view.setText(loading);
        total_score_view.setText(loading);
        setCertFields(loading, loading, loading, loading, loading);

        UrlResolver.resolve(qr, (resolvedUrl, hops) -> runOnUiThread(() -> {

            finalResolvedUrl = resolvedUrl;
            resolved_view.setText(resolvedUrl);

            ArrayList<String> finalSafeHops =
                    (hops == null) ? new ArrayList<>() : new ArrayList<>(hops);

            if (finalSafeHops.isEmpty()) {
                finalSafeHops.add(qr);
            }

            hops_count_view.setText(String.valueOf(Math.max(0, finalSafeHops.size() - 1)));

            StringBuilder chain = new StringBuilder();
            for (int i = 0; i < finalSafeHops.size(); i++) {
                chain.append(i + 1).append(": ").append(finalSafeHops.get(i)).append("\n");
            }
            hops_chain_view.setText(chain.toString());

            int heuristicScore = HeuristicAnalyzer.getScoreFromHops(finalSafeHops);

            final boolean[] gsbDone = {false};
            final boolean[] ptDone = {false};
            final boolean[] certDone = {false};

            final String[] gsbResultHolder = {null};
            final PhishTankChecker.PhishCheckResult[] ptResultHolder = {null};
            final CertificateAnalyzer.CertResult[] certResultHolder = {null};

            Runnable maybeContinue = () -> {
                if (!gsbDone[0] || !ptDone[0] || !certDone[0]) return;

                String gsbResult = gsbResultHolder[0];
                PhishTankChecker.PhishCheckResult ptResult = ptResultHolder[0];
                CertificateAnalyzer.CertResult certResult = certResultHolder[0];

                boolean phishHit = (ptResult == PhishTankChecker.PhishCheckResult.PHISHING);

                // --- GSB ---
                String gsbDisplay = getString(R.string.gsb_safe);
                if (GoogleSafeBrowsing.DANGEROUS.equals(gsbResult)) {
                    gsbDisplay += " (+5)";
                }

                // --- PhishTank ---
                String phishDisplay = getString(R.string.phish_no_unknown);
                if (ptResult == PhishTankChecker.PhishCheckResult.PHISHING) {
                    phishDisplay = getString(R.string.phish_yes) + " (+5)";
                }

                // --- Certificate ---
                applyCertDisplay(certResult);

                // --- Risk ---
                String riskOutput = RiskClassifier.classify(
                        gsbResult,
                        phishHit,
                        heuristicScore,
                        certResult
                );

                String[] parts = riskOutput.split("\\|");
                String finalRisk = parts[0];
                int finalScore = Integer.parseInt(parts[1]);
                int heuristicDisplay = Integer.parseInt(parts[2]);

                // --- Heuristic warnings (REAL SCORES) ---
                LinkedHashMap<String, ArrayList<String[]>> breakdown =
                        HeuristicAnalyzer.getHopBreakdown(finalSafeHops);

                StringBuilder warningsText = new StringBuilder();

                for (String hop : breakdown.keySet()) {
                    warningsText.append(hop).append("\n");

                    for (String[] w : Objects.requireNonNull(breakdown.get(hop))) {
                        String message = w[0];
                        int score = Integer.parseInt(w[1]);

                        if (score > 0) {
                            warningsText.append("  - ")
                                    .append(message)
                                    .append(" (+")
                                    .append(score)
                                    .append(")\n");
                        } else {
                            warningsText.append("  - ")
                                    .append(message)
                                    .append("\n");
                        }
                    }
                    warningsText.append("\n");
                }

                // redirect penalty
                if (finalSafeHops.size() > 5) {
                    warningsText.append("Too many redirects (+2)\n");
                }

                String warnings = warningsText.toString().trim();
                if (warnings.isEmpty()) warnings = getString(R.string.none);

                // Apply UI
                gsb_view.setText(gsbDisplay);
                phish_tank_view.setText(phishDisplay);
                score_view.setText(String.valueOf(heuristicDisplay));
                warnings_view.setText(warnings);

                String totalScoreText = getString(R.string.score) + ": " + finalScore;

                switch (finalRisk) {
                    case "MALICIOUS":
                        safety_view.setText(getString(R.string.risk_dangerous));
                        safety_view.setTextColor(Color.RED);
                        total_score_view.setText(totalScoreText);
                        total_score_view.setTextColor(Color.RED);
                        open_browser_button.setEnabled(false);
                        break;

                    case "SUSPICIOUS":
                        safety_view.setText(getString(R.string.risk_suspicious));
                        safety_view.setTextColor(Color.rgb(255, 140, 0));
                        total_score_view.setText(totalScoreText);
                        total_score_view.setTextColor(Color.rgb(255, 140, 0));
                        open_browser_button.setEnabled(true);
                        break;

                    case "SAFE":
                        safety_view.setText(getString(R.string.risk_safe));
                        safety_view.setTextColor(Color.rgb(0, 128, 0));
                        total_score_view.setText(totalScoreText);
                        total_score_view.setTextColor(Color.rgb(0, 128, 0));
                        open_browser_button.setEnabled(true);
                        break;
                }
            };

            GoogleSafeBrowsing.checkUrl(resolvedUrl, result -> runOnUiThread(() -> {
                gsbResultHolder[0] = result;
                gsbDone[0] = true;
                maybeContinue.run();
            }));

            PhishTankChecker.checkUrl(resolvedUrl, result -> runOnUiThread(() -> {
                ptResultHolder[0] = result;
                ptDone[0] = true;
                maybeContinue.run();
            }));

            CertificateAnalyzer.checkUrl(resolvedUrl, originalUrl, result -> {
                certResultHolder[0] = result;
                certDone[0] = true;
                maybeContinue.run();
            });

        }));

        setupButtons();

        open_browser_button.setOnClickListener(v -> {
            if (finalResolvedUrl != null) {
                startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(finalResolvedUrl)));
            }
        });
    }

    @SuppressLint("SetTextI18n")
    private void applyCertDisplay(CertificateAnalyzer.CertResult r) {

        if (r == null) {
            setCertFields("-", "-", "-", "-", "-");
            return;
        }

        // --- TIMEOUT ---
        if (r.timeout) {
            setCertFields(
                    getString(R.string.cert_timeout),
                    "-", "-", "-", "-"
            );
            cert_status_view.setTextColor(Color.DKGRAY);
            return;
        }

        // --- INVALID CERT ---
        if (!r.valid) {

            String status;

            if (r.checkedUrl == null) {
                status = getString(R.string.cert_no_https);
            } else if (r.handshakeFailed) {
                status = getString(R.string.cert_handshake_failed) + " (+3)";
            } else {
                status = getString(R.string.cert_invalid);
            }

            setCertFields(status, "-", "-", "-", "-");
            cert_status_view.setTextColor(Color.RED);
            return;
        }

        // --- VALID CERT ---
        cert_status_view.setText(getString(R.string.cert_valid));
        cert_status_view.setTextColor(Color.rgb(0, 128, 0));

        // issuer
        cert_issuer_view.setText(r.issuer != null ? r.issuer : "-");
        cert_issuer_view.setTextColor(Color.BLACK);

        // expiry
        if (r.notYetValid) {
            cert_expiry_view.setText(getString(R.string.cert_not_yet_valid) + " (+1)");
            cert_expiry_view.setTextColor(Color.rgb(255, 140, 0));
        } else if (r.expired) {
            cert_expiry_view.setText(getString(R.string.cert_expired) + " (+2)");
            cert_expiry_view.setTextColor(Color.RED);
        } else {
            cert_expiry_view.setText(getString(R.string.cert_not_expired));
            cert_expiry_view.setTextColor(Color.rgb(0, 128, 0));
        }

        // self-signed
        if (r.selfSigned) {
            cert_self_signed_view.setText(getString(R.string.cert_self_signed_yes) + " (+1)");
            cert_self_signed_view.setTextColor(Color.rgb(255, 140, 0));
        } else {
            cert_self_signed_view.setText(getString(R.string.cert_self_signed_no));
            cert_self_signed_view.setTextColor(Color.rgb(0, 128, 0));
        }

        // domain match
        if (r.domainMatch) {
            cert_domain_match_view.setText(getString(R.string.cert_domain_match_yes));
            cert_domain_match_view.setTextColor(Color.rgb(0, 128, 0));
        } else {
            cert_domain_match_view.setText(getString(R.string.cert_domain_match_no) + " (+2)");
            cert_domain_match_view.setTextColor(Color.RED);
        }
    }

    private void setCertFields(String status, String issuer,
                               String expiry, String selfSigned, String domainMatch) {
        cert_status_view.setText(status);
        cert_issuer_view.setText(issuer);
        cert_expiry_view.setText(expiry);
        cert_self_signed_view.setText(selfSigned);
        cert_domain_match_view.setText(domainMatch);
    }

    private void setupButtons() {
        results_scan_button.setOnClickListener(v -> {
            startActivity(new Intent(this, ScannerActivity.class));
            finish();
        });

        home_return_button.setOnClickListener(v -> {
            startActivity(new Intent(this, MainActivity.class));
            finish();
        });
    }
}