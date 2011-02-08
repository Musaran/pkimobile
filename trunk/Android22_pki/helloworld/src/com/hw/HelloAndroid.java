package com.hw;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

public class HelloAndroid extends Activity implements OnClickListener
{
	private TextView textArea = null;
	private Button menuButton = null;
	private PKI pkiKeys = null;
	private String serverPublic = "";
	
	/* -------------------- GUI -------------------- */
    @Override
    public void onCreate(Bundle savedInstanceState)
    {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        menuButton = (Button)findViewById(R.id.buttonmenu);
        menuButton.setOnClickListener(this);
        textArea = (TextView)findViewById(R.id.tv);
        pkiKeys = new PKI(this);
    }
    
    @Override
	public void onClick(View v)
	{
		this.getMenu();
	}
    
    public void print(String text)
    {
   		textArea.append("\n"+text);
    }
    
    public void getMenu()
    {
    	if(pkiKeys.isKeyLoaded())
    	{
	    	final CharSequence[] items = {"Regénérer", "Get Pub Server", "Env. pub cl", "Connexion"};
	    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
	    	builder.setTitle("Menu");
	    	builder.setItems(items, new MenuListener(this));
	    	builder.create().show();
    	}
    	else
    	{
    		final CharSequence[] items = {"Générer", "Charger"};
	    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
	    	builder.setTitle("Menu");
	    	builder.setItems(items, new ShortMenuListener(this));
	    	builder.create().show();
    	}
    }

    /* -------------------- KEYS MANAGEMENT -------------------- */
	public void keyGen()
	{
		long start = System.currentTimeMillis();
		pkiKeys.generateKeys();
		long duration = System.currentTimeMillis() - start;
		this.print("Clés générées en "+duration+"ms.");
		start = System.currentTimeMillis();
		pkiKeys.saveKeysToFile();
		long duration2 = System.currentTimeMillis() - start;
		this.print("Clés enregistrées en "+duration2+"ms.");
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
		// On signe un message CHALLENGE
		long start = System.currentTimeMillis();
		String si = pkiKeys.getSignature("CHALLENGE");
		long duration = System.currentTimeMillis() - start;
		this.print("Signé 'CHALLENGE' en "+duration+"ms.");
		
		// On le crypte avec la clé publique du serveur
		
	}

	public void keyLoadFromFile()
	{
		long start = System.currentTimeMillis();
		pkiKeys.loadKeysFromFile();
		long duration = System.currentTimeMillis() - start;
		this.print("Clés chargées en "+duration+"ms.");
		this.print("Clé publique: "+pkiKeys.getPublicKey().getEncoded());
	}
	
	/* ------------- STORAGE -------------- */
	public byte[] getFile(String filename)
	{
		byte[] encodedFile = null;
		try
		{
			FileInputStream fis = openFileInput(filename);
			encodedFile = new byte[fis.available()];
			fis.read(encodedFile);
			fis.close();
		}
		catch(Exception e) { e.printStackTrace(); }
		return encodedFile;
	}
	
	public void setFile(String filename, byte[] content)
	{
		try
		{
			FileOutputStream fos = openFileOutput(filename, Context.MODE_PRIVATE);
			fos.write(content);
			fos.close();
		}
		catch(Exception e) { e.printStackTrace(); }
	}
	
	/* ------------- UTILS ---------------- */
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
		catch (Exception e) {e.printStackTrace();}
		return res;
	}
}