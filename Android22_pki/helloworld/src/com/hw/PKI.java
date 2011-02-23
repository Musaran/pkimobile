package com.hw;

import java.io.DataOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import android.content.Context;

public class PKI
{
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private boolean keyLoaded = false;
	
	private HelloAndroid parent;
	
	private final String filePrivate = "private.key";
	private final String filePublic = "public.key";

	public PKI(HelloAndroid ha){parent = ha;}
	
	/* -------------------- KEYS MANAGEMENT -------------------- */
	/**
	 * This function generates a pair of keys
	 */
	public void generateKeys()
	{
		try
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize( 1024 );
			KeyPair pair = keyGen.generateKeyPair();
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
			keyLoaded = true;
		}
		catch(Exception e) {e.printStackTrace(); keyLoaded = false;}
	}
	
	/**
	 * This function try to load the private and the public key from specific file on the phone
	 */
	public void loadKeysFromFile()
	{
		try
		{
			// Public key
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(parent.getFile(filePublic));
			publicKey  = keyFactory.generatePublic(publicKeySpec);
			
			// Private key
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(parent.getFile(filePrivate));
			privateKey = keyFactory.generatePrivate(privateKeySpec);
			
			keyLoaded = true;
		}
		catch(Exception e) {e.printStackTrace(); keyLoaded = false;}
	}
	
	/**
	 * This function store the current keys into files for further uses
	 */
	public void saveKeysToFile()
	{
		if(keyLoaded)
		{
			X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());
			PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
			parent.setFile(filePrivate, pkcs8EncodedKeySpec.getEncoded());
			parent.setFile(filePublic, x509EncodedKeySpec.getEncoded());
		}
	}
	
	/**
	 * This function return a public key which is read drom a file
	 * @param filename the file containing the public key
	 * @return the public key
	 */
	public PublicKey getPublicKeyFromFile(String filename)
	{
		try
		{
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(parent.getFile(filename));
			return(keyFactory.generatePublic(publicKeySpec));
		}
		catch(Exception e) {e.printStackTrace();}
		return null;
	}

	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------      PKI       --------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/**
	 * Verify if the signature is the good one
	 * @param text	the signed text
	 * @param sign	the signature
	 * @param pub	the public key used to verify the signature
	 * @return		true if the signature is the good one
	 */
	public boolean verifySignature( byte[] text, byte[] sign, PublicKey pub )
	{
		try {
			Signature rsa = Signature.getInstance("SHA1withRSA");
			rsa.initVerify( pub );
			rsa.update( text );
			boolean res = rsa.verify( sign );
			return res;
		}catch( Exception e ){e.printStackTrace();}
		return false;
	}
	
	/**
	 * Get the signature of a text
	 * @param text	the text which must be signed
	 * @param pri	the private key
	 * @return		the signature
	 */
	public byte[] getSignature( byte[] text, PrivateKey pri )
	{
		try
		{
			Signature dsa = Signature.getInstance("SHA1withRSA");
			dsa.initSign( pri );
			dsa.update( text );
			byte[] signature = dsa.sign();
			return signature;
		}
		catch( Exception e ){e.printStackTrace();}
		return null;
	}
	
	/**
	 * Encrypt a text
	 * @param btext	the text which must be crypted
	 * @param pub	the public key
	 * @return		the crypted text
	 */
	public byte[] encryptText( byte[] btext, Key pub )
	{
		try
		{
			DataOutputStream eOutRSA = new DataOutputStream(parent.openFileOutput("temp.m", Context.MODE_PRIVATE));
			Cipher cf = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // NoPadding
			cf.init(Cipher.ENCRYPT_MODE, pub);
			/*int bigcount = 0;
			for(int i = 0; i < btext.length; i+=117)
			{
				byte[] te = new byte[117]; int count = 0;
				for(int j = i; j < (i+117); j++)
				{
					if(j < btext.length)
					{
						te[count] = btext[j];
						count++;
						bigcount++;
					}
				}
				
				byte[] encodedMsg = cf.doFinal(te);
				eOutRSA.write(encodedMsg, 0, encodedMsg.length);
			}*/
			cf.update(btext);
			byte[] encodedMsg = cf.doFinal();
			eOutRSA.write(encodedMsg, 0, encodedMsg.length);
			//parent.print(bigcount+" bytes encodés.");
			eOutRSA.close();
			byte[] res = parent.getFile("temp.m");
			parent.deleteFile("temp.m");
			return res;
		}
		catch( Exception e ){e.printStackTrace();}
		return null;
	}

	// GETTER / SETTER
	public PrivateKey getPrivateKey() { return privateKey; }
	public PublicKey getPublicKey() { return publicKey; }
	public boolean isKeyLoaded() { return keyLoaded; }
}
