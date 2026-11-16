package abinfotech.in;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;

public class listCertificate extends Activity implements RadioGroup.OnCheckedChangeListener {

    private String[] strCertList = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if (intent != null && intent.getExtras() != null) {
            strCertList = intent.getStringArrayExtra("CertList");
        }

        if (strCertList == null) {
            strCertList = new String[0];
        }

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 40, 32, 40);
        layout.setBackgroundColor(Color.parseColor("#0F172A")); // Slate dark background

        TextView title = new TextView(this);
        title.setText("Select Digital Certificate");
        title.setTextSize(18);
        title.setTextColor(Color.WHITE);
        title.setPadding(0, 0, 0, 24);
        layout.addView(title);

        RadioGroup group = new RadioGroup(this);
        for (int i = 0; i < strCertList.length; i++) {
            RadioButton tempButton = new RadioButton(this);
            tempButton.setPadding(24, 20, 24, 20);
            tempButton.setText(strCertList[i]);
            tempButton.setTextColor(Color.parseColor("#E2E8F0"));
            tempButton.setId(i + 100);
            group.addView(tempButton, LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        }

        layout.addView(group);
        setContentView(layout);

        group.setOnCheckedChangeListener(this);
    }

    @Override
    public void onCheckedChanged(RadioGroup group, int checkedId) {
        int index = checkedId - 100;
        if (strCertList != null && index >= 0 && index < strCertList.length) {
            Intent resultIntent = new Intent();
            Bundle bundle = new Bundle();
            bundle.putInt("certIndex", index);
            resultIntent.putExtras(bundle);
            setResult(Activity.RESULT_OK, resultIntent);
            finish();
        }
    }
}
