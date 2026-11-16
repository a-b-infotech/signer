package abinfotech.in;

import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.VideoView;

import androidx.appcompat.app.AppCompatActivity;

public class SplashActivity extends AppCompatActivity {

    private VideoView videoView;
    private boolean isNavigated = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_splash);

        videoView = findViewById(R.id.splash_video_view);
        View root = findViewById(R.id.splash_root);
        View btnSkip = findViewById(R.id.btn_skip);

        String videoPath = "android.resource://" + getPackageName() + "/" + R.raw.splash_video;
        Uri videoUri = Uri.parse(videoPath);

        videoView.setVideoURI(videoUri);

        videoView.setOnCompletionListener(mp -> navigateToMain());
        videoView.setOnErrorListener((mp, what, extra) -> {
            navigateToMain();
            return true;
        });

        root.setOnClickListener(v -> navigateToMain());
        if (btnSkip != null) {
            btnSkip.setVisibility(View.VISIBLE);
            btnSkip.setOnClickListener(v -> navigateToMain());
        }

        // Safety fallback timeout in case video fails to fire completion
        new Handler(Looper.getMainLooper()).postDelayed(() -> {
            if (!isFinishing() && !isNavigated) {
                navigateToMain();
            }
        }, 8000);

        videoView.start();
    }

    private synchronized void navigateToMain() {
        if (isNavigated) return;
        isNavigated = true;

        if (videoView != null && videoView.isPlaying()) {
            videoView.stopPlayback();
        }

        Intent intent = new Intent(SplashActivity.this, MainActivity.class);
        // Pass any intent data (e.g. if launched with a PDF file) to MainActivity
        if (getIntent() != null && getIntent().getData() != null) {
            intent.setData(getIntent().getData());
            intent.setAction(getIntent().getAction());
        }
        startActivity(intent);
        overridePendingTransition(android.R.anim.fade_in, android.R.anim.fade_out);
        finish();
    }
}