package com.hw;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public class HelloAndroid extends Activity {
	
	TextView tv = null;
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        PKI.test(this);
    }
    
    public void print(String text) {
    	if(tv == null)
    		tv = (TextView)findViewById(R.id.tv);
    	tv.append("\n"+text);
    }
}