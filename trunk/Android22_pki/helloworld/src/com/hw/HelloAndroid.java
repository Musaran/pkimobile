package com.hw;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.security.PublicKey;
import java.util.Arrays;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

public class HelloAndroid extends Activity implements OnClickListener
{
	private TextView textArea = null;
	private Button menuButton = null;
	private PKI pkiKeys = null;
	private EditText iAdress = null;
	
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
        iAdress = (EditText)findViewById(R.id.iAdress);
        pkiKeys = new PKI(this);
    }
    
    @Override
	public void onClick(View v)
	{
		this.getMenu();
	}
    
    /**
     * Append a text in the output
     * @param text the text to print
     */
    public void print(String text)
    {
   		textArea.append("\n"+text);
    }
    
    /**
     * Remove all the text in the output
     */
    public void clearText()
    {
    	textArea.setText("");
    }
    
    /**
     * Show the menu when the user press the menu button
     */
    public void getMenu()
    {
    	if(pkiKeys.isKeyLoaded())
    	{
    		// If the keys are loaded we show the full menu
	    	final CharSequence[] items = {"Regénérer", "Recharger", "Get Pub Server", "Env. pub cl", "Connexion", "Decrypt", "TOUT", "Clear"};
	    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
	    	builder.setTitle("Menu");
	    	builder.setItems(items, new MenuListener(this));
	    	builder.create().show();
    	}
    	else
    	{
    		// Or just the choice between generate and load keys...
    		final CharSequence[] items = {"Générer", "Charger"};
	    	AlertDialog.Builder builder = new AlertDialog.Builder(this);
	    	builder.setTitle("Menu");
	    	builder.setItems(items, new ShortMenuListener(this));
	    	builder.create().show();
    	}
    }

    /* -------------------- KEYS MANAGEMENT -------------------- */
    /**
     * Benchmark generation of keys
     */
	public void keyGen()
	{
		long start = System.currentTimeMillis();
		pkiKeys.generateKeys(); // Generation
		long duration = System.currentTimeMillis() - start;
		this.print("Clés générées en "+duration+"ms.");
		start = System.currentTimeMillis();
		pkiKeys.saveKeysToFile(); // Saving into files
		long duration2 = System.currentTimeMillis() - start;
		this.print("Clés enregistrées en "+duration2+"ms.");
	}
	
	/**
     * Benchmark retrieving of servers' public key
     */
	public void keyGetServer()
	{
		long start = System.currentTimeMillis();
		getURL("http://williamjouot.com/pki/public.der", "temp.l");
		long duration = System.currentTimeMillis() - start;
		this.print("Clé publique reçue en "+duration+"ms.");
		serverKey = pkiKeys.getPublicKeyFromFile("temp.l");
		deleteFile("temp.l");
	}
	
	/**
	 * Send our public key to the server
	 */
	public void keySetServer()
	{
		if(serverKey != null)
		{
			// Building the message
			// Message is 1 byte == 2 then the public key
			byte[] a = {2}; // 2 = SetKey
			byte[] key = pkiKeys.getPublicKey().getEncoded();
			byte[] msgfinal = new byte[1 + key.length];
			System.arraycopy(a, 0, msgfinal, 0, 1);
			System.arraycopy(key, 0, msgfinal, 1, key.length);
			this.print("Envoi de la cle au serveur...");
			
			// We encrypt it with the public key of the server
			long start = System.currentTimeMillis();
			byte[] en = pkiKeys.encryptText(msgfinal, serverKey); // Encryption
			long duration2 = System.currentTimeMillis() - start;
			this.print("Chiffrage en "+duration2+"ms.");
			
			// We send it.
			ServerDialog sd = new ServerDialog();
			byte[] response = sd.getFromServer(iAdress.getText().toString(), 1023, en);
			
			// We look at the response
			if(response[0] == 1)
				this.print("OK!");
			else
				this.print("Erreur!");
		}
		else
			Toast.makeText(getApplicationContext(), "No Server Key", Toast.LENGTH_SHORT).show();
	}
	
	/**
	 * Try to authenticate with the server
	 */
	public void keyConnect()
	{
		if(serverKey != null)
		{
			byte[] message = "CHALLENGE".getBytes();
			
			// We sign a CHALLENGE message
			long start = System.currentTimeMillis();
			byte[] sign = pkiKeys.getSignature(message, pkiKeys.getPrivateKey()); // Sign
			long duration = System.currentTimeMillis() - start;
			this.print("Signé 'CHALLENGE' en "+duration+"ms.");
			
			// We build the message
			byte[] a = {1}; // 1 = Connexion
			byte[] msgfinal = new byte[message.length + 1 + sign.length];
			System.arraycopy(a, 0, msgfinal, 0, 1);
			System.arraycopy(message, 0, msgfinal, 1, message.length);
			System.arraycopy(sign, 0, msgfinal, (1 + message.length), sign.length);
			
			// We encrypt it
			start = System.currentTimeMillis();
			byte[] en = pkiKeys.encryptText(msgfinal, serverKey);
			long duration2 = System.currentTimeMillis() - start;
			this.print("Chiffrage en "+duration2+"ms.");
			
			// We send it
			start = System.currentTimeMillis();
			ServerDialog sd = new ServerDialog();
			this.print(en.length+" bytes à envoyer...");
			byte[] response = sd.getFromServer(iAdress.getText().toString(), 1023, en);
			long duration3 = System.currentTimeMillis() - start;
			this.print("Envoi et réponse serveur en "+duration3+"ms");
			if(response.length == 1)
				this.print("Erreur.");
			else
			{
				byte[] waitedmsg = "AUTH".getBytes();
				byte[] rcvmsg = new byte[waitedmsg.length];
				System.arraycopy(response, 0, rcvmsg, 0, waitedmsg.length); // BOF inside
				if(Arrays.equals(waitedmsg, rcvmsg))
				{
					// Yep, so we check the signature
					System.out.println("Recu AUTH... Verification de la signature...");
					int signlgth = (response.length - waitedmsg.length);
					byte[] rcvsign = new byte[signlgth];
					System.arraycopy(response, waitedmsg.length, rcvsign, 0, signlgth);
					start = System.currentTimeMillis();
					boolean res = pkiKeys.verifySignature( waitedmsg, rcvsign, serverKey );
					long duration4 = System.currentTimeMillis() - start;
					this.print("Verification de la signature en "+duration4+"ms");
					if(res)
					{
						this.print("OK!");
					}
					else
					{
						this.print("Erreur lors de la verification de la signature");
					}
				}
				else
				{
					this.print("Mauvais message recu");
				}
			}
		}
		else
			Toast.makeText(getApplicationContext(), "No Server Key", Toast.LENGTH_SHORT).show();
	}

	public void keyDecrypt()
	{
		if(serverKey != null)
		{
			ServerDialog sd = new ServerDialog();
			byte[] en = {3};
			byte[] ask = pkiKeys.encryptText(en, serverKey);
			byte[] response = sd.getFromServer(iAdress.getText().toString(), 1023, ask);
			if(response.length == 1 && response[0] == 2)
			{
				this.print("Erreur serveur.");
			}
			else
			{
				long start = System.currentTimeMillis();
				byte[] decrypt = pkiKeys.decryptText(response, pkiKeys.getPrivateKey());
				String res = new String(decrypt);
				long duration = System.currentTimeMillis() - start;
				this.print("Decryptage du message "+res+" en "+duration+"ms");
			}
		}
		else
			Toast.makeText(getApplicationContext(), "No Server Key", Toast.LENGTH_SHORT).show();
	}
	
	public void keyAll()
	{
		long start = System.currentTimeMillis();
		keyLoadFromFile();
		keyGetServer();
		keySetServer();
		keyConnect();
		long duration = System.currentTimeMillis() - start;
		this.print("TOUT en "+duration+"ms");
	}
	
	/**
	 * Load private and public keys from the phone
	 */
	public void keyLoadFromFile()
	{
		long start = System.currentTimeMillis();
		pkiKeys.loadKeysFromFile();
		long duration = System.currentTimeMillis() - start;
		this.print("Clés chargées en "+duration+"ms.");
	}
	
	/**
	 * Print the first 20 bytes of an array of bytes. Used for debug.
	 * @param e	the array of byte
	 * @return the represented string
	 */
	public String printBytes(byte[] e)
	{
		String l = "";
		int max = 20;
		if(e.length < 20) max = e.length;
		for(int i=0; i < max; i++) {
			l += e[i]+"/";
		}
		return l;
	}
	
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------    FICHIERS    --------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/**
	 * Get the array of bytes from a specified file
	 * @param filename	the file to read
	 * @return the array of bytes in the file
	 */
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
	
	/**
	 * Write an array of bytes in a file
	 * @param filename	the file to write into
	 * @param content	the content to write
	 */
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
	/**
	 * Return the array of bytes from an URL
	 * @param link	the url
	 * @return an array of bytes
	 */
	public void getURL(String urlarg, String filename)
	{
		// BEAUCOUP plus simple d'enregistrer dans un fichier temporaire
		// En effet si on fait une string au lieu de byte[], ça ne marche pas.
		try
		{
			URL url = new URL(urlarg);
			URLConnection connection = url.openConnection();
			InputStream input = connection.getInputStream();
			FileOutputStream writeFile = openFileOutput(filename, Context.MODE_PRIVATE);
			byte[] buffer = new byte[1024];
			int read;
			while ((read = input.read(buffer)) > 0)
				writeFile.write(buffer, 0, read);
			writeFile.flush();
		}
		catch (Exception e) {e.printStackTrace();}
	}
}