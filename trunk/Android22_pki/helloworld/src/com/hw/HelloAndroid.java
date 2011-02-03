package com.hw;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.net.URL;

import android.app.Activity;
import android.app.AlertDialog;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class HelloAndroid extends Activity implements OnClickListener
{
	TextView textarea = null;
	Button buttonmenu = null;
	PKI pki = null;
	String serverPublic = "";
	
    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        buttonmenu = (Button)findViewById(R.id.buttonmenu);
        buttonmenu.setOnClickListener(this);
        textarea = (TextView)findViewById(R.id.tv);
        pki = new PKI(this);
    }
    
    @Override
	public void onClick(View v)
	{
		this.getMenu();
	}
    
    public void print(String text)
    {
   		textarea.append("\n"+text);
    }
    
    public void getMenu()
    {
    	final CharSequence[] items = {"Générer", "Get Pub Server", "Env. pub cl", "Connexion"};
    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
    	builder.setTitle("Menu");
    	builder.setItems(items, new MenuListener(this));
    	builder.create().show();
    }

	public void keyGen()
	{
		long start = System.currentTimeMillis();
		pki.generateKeys();
		long duration = System.currentTimeMillis() - start;
		this.print("Clés générées en "+duration+"ms.");
	}
	
	public void keyGetServer()
	{
		long start = System.currentTimeMillis();
		serverPublic = getURL("http://williamjouot.com/pki/pki.php?op=1");
		this.print(serverPublic);
		long duration = System.currentTimeMillis() - start;
		this.print("Clé publique reçue en "+duration+"ms.");
	}
	
	public void keySetServer()
	{
		
	}
	
	public void keyConnect()
	{
		String si = pki.sign("CHALLENGE");
		
	}
	
	public String getURL(String urlarg)
	{
		String res = "";
		try {
			URL u;
			InputStream is = null;
			DataInputStream dis;
			String s;
			u = new URL(urlarg);
			is = u.openStream();
			dis = new DataInputStream(new BufferedInputStream(is));
			while ((s = dis.readLine()) != null) {
				res += s;
			}
			is.close();
		}
		catch (Exception e) {e.printStackTrace(); }
		return res;
	}
}