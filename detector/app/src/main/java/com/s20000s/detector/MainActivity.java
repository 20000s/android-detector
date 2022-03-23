package com.s20000s.detector;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

import com.s20000s.detector.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    // Used to load the 'native-lib' library on application startup.
    static {
        System.loadLibrary("native-lib");
    }

    private static final String XPOSED_HELPERS = "de.robv.android.xposed.XposedHelpers";
    private static final String XPOSED_BRIDGE = "de.robv.android.xposed.XposedBridge";

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());


        findViewById(R.id.b1).setOnClickListener(this);
        findViewById(R.id.b2).setOnClickListener(this);
        findViewById(R.id.b3).setOnClickListener(this);
        findViewById(R.id.b4).setOnClickListener(this);
        findViewById(R.id.b5).setOnClickListener(this);
        findViewById(R.id.b6).setOnClickListener(this);

    }

    @Override
    public void onClick(View v) {
        switch (v.getId()){
            case R.id.b1:
                TextView v1 = findViewById(R.id.ptrace);
                v1.setText(Antiptrace());
                break;
            case R.id.b2:
                TextView v2 = findViewById(R.id.root);
                v2.setText(AntiRoot());
                break;
            case R.id.b3:
                TextView v3 = findViewById(R.id.frida);
                v3.setText(AntiFrida());
                break;
            case R.id.b4:
                TextView v4 = findViewById(R.id.xposed);
                v4.setText(AntiXposed());
                break;
            case R.id.b5:
                TextView v5 = findViewById(R.id.riru);
                v5.setText(AntiRiru());
                break;
            case R.id.b6:
                TextView v6 = findViewById(R.id.magisk);
                v6.setText(AntiMagisk());
                break;
        }
    }

    /**
     * A native method that is implemented by the 'native-lib' native library,
     * which is packaged with this application.
     */
    public static native String Antiptrace();
    public static native String AntiRoot();
    public static native String AntiFrida();
    public static native String AntiXposed();
    public static native String AntiRiru();
    public static native String AntiMagisk();


}