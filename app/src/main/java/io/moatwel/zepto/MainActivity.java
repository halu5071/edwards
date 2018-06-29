package io.moatwel.zepto;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;

import io.moatwel.crypto.HashAlgorithm;
import io.moatwel.crypto.eddsa.Edwards;
import io.moatwel.crypto.eddsa.ed25519.Ed25519Provider;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        new Edwards();
        new Edwards(new Ed25519Provider(HashAlgorithm.SHA3_512));
    }
}
