package com.hw;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.PublicKey;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

public class HelloAndroid extends Activity implements OnClickListener
{
	private TextView textArea = null;
	private Button menuButton = null;
	private PKI pkiKeys = null;
	
	private PublicKey serverKey = null;
	
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
    
    public void clearText()
    {
    	textArea.setText("");
    }
    
    public void getMenu()
    {
    	if(pkiKeys.isKeyLoaded())
    	{
	    	final CharSequence[] items = {"Regénérer", "Recharger", "Get Pub Server", "Env. pub cl", "Connexion", "Clear"};
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
		getURL("http://williamjouot.com/pki/public.der", "temp.l");
		long duration = System.currentTimeMillis() - start;
		this.print("Clé publique reçue en "+duration+"ms.");
		serverKey = pkiKeys.getPublicKeyFromFile("temp.l");
		//this.print("Pub: "+serverKey.getFormat()+" - "+serverKey.getEncoded());
		deleteFile("temp.l");
	}
	
	public void keySetServer()
	{
		
	}
	
	public void keyConnect()
	{
		if(serverKey != null)
		{
			byte[] message = "CHALLENGE".getBytes();
			
			// On signe un message CHALLENGE
			long start = System.currentTimeMillis();
			byte[] sign = pkiKeys.getSignature(message);
			long duration = System.currentTimeMillis() - start;
			this.print("Signé 'CHALLENGE' en "+duration+"ms.");
			
			// On concat les deux array de byte
			// Apparement rien dans l'API java permet de le faire automatiquement. Go mains nues :
			byte[] inter = ";-;".getBytes(); // Signe entre la signature et le message
			byte[] msgfinal = new byte[sign.length + inter.length + message.length];
			System.arraycopy(sign, 0, msgfinal, 0, sign.length);
			System.arraycopy(inter, 0, msgfinal, sign.length, inter.length);
			System.arraycopy(message, 0, msgfinal, (sign.length + inter.length), message.length); 
			
			// DEBUG
			String l = "";
			for(int i=0; i < 20; i++)
				l += msgfinal[i]+"/";
			this.print(l);
			
			// On le crypte avec la clé publique du serveur
			start = System.currentTimeMillis();
			byte[] en = pkiKeys.encryptText(msgfinal, serverKey);
			long duration2 = System.currentTimeMillis() - start;
			//this.clearText();
			this.print("Chiffrage en "+duration2+"ms.");//: [0]"+en[0]+" [H]"+en.hashCode());
			
			// DEBUG
			/*String l = "";
			for(int i=0; i < en.length; i++)
				l += en[i]+"/";
			this.print(l);*/
			
			// Y a plus qu'à envoyer
			start = System.currentTimeMillis();
			ServerDialog sd = new ServerDialog();
			this.print(en.length+" bytes à envoyer...");
			byte[] response = sd.getFromServer("192.168.0.21", 1023, en);
			long duration3 = System.currentTimeMillis() - start;
			this.print("Envoi et réponse serveur en "+duration3+"ms : "+response);
		}
		else
			Toast.makeText(getApplicationContext(), "No Server Key", Toast.LENGTH_SHORT).show();
	}

	public void keyLoadFromFile()
	{
		long start = System.currentTimeMillis();
		pkiKeys.loadKeysFromFile();
		long duration = System.currentTimeMillis() - start;
		this.print("Clés chargées en "+duration+"ms.");
		//this.print("Clé publique: "+pkiKeys.getPublicKey().getEncoded());
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
	public void getURL(String urlarg, String filename)
	{
		// BEAUCOUP plus simple d'enregistrer dans un fichier temporaire
		// En effet si on fait une string au lieu de byte[], ça ne marche pas.
		try
		{
			URL url = new URL(urlarg);
			URLConnection connection = url.openConnection();
			InputStream input = connection.getInputStream();
			FileOutputStream writeFile = openFileOutput(filename, Context.MODE_PRIVATE);//new FileOutputStream(filename);
			byte[] buffer = new byte[1024];
			int read;
			while ((read = input.read(buffer)) > 0)
				writeFile.write(buffer, 0, read);
			writeFile.flush();
		}
		catch (Exception e) {e.printStackTrace();}
	}
}