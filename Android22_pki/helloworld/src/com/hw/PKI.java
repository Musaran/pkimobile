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
	
	private final String cAlgorithm = "RSA"; // DSA
	private final String sAlgorithm = "SHA1withRSA"; //SHA1withDSA

	public PKI(HelloAndroid ha){parent = ha;}
	
	/* -------------------- KEYS MANAGEMENT -------------------- */
	// Generate Keys
	public void generateKeys()
	{
		try
		{
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(cAlgorithm);
			keyGen.initialize( 1024 );
			KeyPair pair = keyGen.generateKeyPair();
			privateKey = pair.getPrivate();
			publicKey = pair.getPublic();
			keyLoaded = true;
		}
		catch(Exception e) {e.printStackTrace(); keyLoaded = false;}
	}
	
	// Load keys from file
	public void loadKeysFromFile()
	{
		try
		{
			KeyFactory keyFactory = KeyFactory.getInstance(cAlgorithm);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(parent.getFile(filePublic));
			publicKey  = keyFactory.generatePublic(publicKeySpec);
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(parent.getFile(filePrivate));
			privateKey = keyFactory.generatePrivate(privateKeySpec);
			keyLoaded = true;
		}
		catch(Exception e) {e.printStackTrace(); keyLoaded = false;}
	}
	
	// Save keys to file
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
	
	public PublicKey getPublicKeyFromFile(String filename)
	{
		try
		{
			KeyFactory keyFactory = KeyFactory.getInstance(cAlgorithm);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(parent.getFile(filename));
			return(keyFactory.generatePublic(publicKeySpec));
		}
		catch(Exception e) {e.printStackTrace();}
		return null;
	}

	/* -------------------- KEYS OPERATIONS -------------------- */
	public byte[] getSignature( byte[] text )
	{
		if(keyLoaded)
		{
			try
			{
				Signature dsa = Signature.getInstance(sAlgorithm);
				dsa.initSign( privateKey );
				dsa.update( text );
				byte[] signature = dsa.sign();
				return signature;
			}
			catch( Exception e ){e.printStackTrace();}
		}
		return null;
	}
	
	public byte[] encryptText( byte[] btext, Key pub )
	{
		try
		{
			DataOutputStream eOutRSA = new DataOutputStream(parent.openFileOutput("temp.m", Context.MODE_PRIVATE));//new FileOutputStream("temp"));
			Cipher cf = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cf.init(Cipher.ENCRYPT_MODE, pub);
			// TODO: Ca bug, le but est de découper des morceaux de 117 bytes (car clé de 1024 donc ((1024 / 8) - 11) bytes)
			int bigcount = 0;
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
			}
			parent.print(bigcount+" bytes encodés.");
			eOutRSA.close();
			byte[] res = parent.getFile("temp.m");
			parent.deleteFile("temp.m");
			return res;
		}
		catch( Exception e ){e.printStackTrace();}
		return null;
	}

	/* DUMPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP */
	/*public boolean verifySignature( String plaintext, String signature )
	{
		if( !keyLoaded ) { parent.print("Pas de clés"); return false; }
		try	{
			Signature dsa = Signature.getInstance(sAlgorithm);
			dsa.initVerify( publicKey );
			dsa.update( plaintext.getBytes() );
			boolean verifies = dsa.verify( getBytes( signature ) );
			//System.out.println("signature verifies: " + verifies);
			return verifies;
		}catch( Exception e ){e.printStackTrace();}
		return false;
	}

	private static String getString( byte[] bytes )
	{
		StringBuffer sb = new StringBuffer();
		for( int i=0; i<bytes.length; i++ )
		{
			byte b = bytes[ i ];
			sb.append( ( int )( 0x00FF & b ) );
			if( i+1 <bytes.length )
			{
				sb.append( "-" );
			}
		}
		return sb.toString();
	}

	private static byte[] getBytes( String str )
	{
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		StringTokenizer st = new StringTokenizer( str, "-", false );
		while( st.hasMoreTokens() )
		{
			int i = Integer.parseInt( st.nextToken() );
			bos.write( ( byte )i );
		}
		return bos.toByteArray();
	}*/

	// GETTER / SETTER
	public PrivateKey getPrivateKey() { return privateKey; }
	public PublicKey getPublicKey() { return publicKey; }
	public boolean isKeyLoaded() { return keyLoaded; }
}
