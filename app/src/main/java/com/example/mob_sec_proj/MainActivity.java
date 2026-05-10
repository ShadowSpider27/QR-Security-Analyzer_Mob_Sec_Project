package com.example.mob_sec_proj;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity extends AppCompatActivity {

    Button scan_button, results_button;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        scan_button = findViewById(R.id.btnScan);
        results_button = findViewById(R.id.btnResults);

        scan_button.setOnClickListener(v ->
                startActivity(new Intent(this, ScannerActivity.class))
        );

        results_button.setOnClickListener(v ->
                startActivity(new Intent(this, ResultActivity.class))
        );
    }
}