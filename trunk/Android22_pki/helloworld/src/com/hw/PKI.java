package com.hw;

import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.StringTokenizer;
import javax.crypto.Cipher;

public class PKI
{
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private boolean keyLoaded = false;
	
	private HelloAndroid parent;
	
	private final String filePrivate = "private.key";
	private final String filePublic = "public.key";
	
	private final String cAlgorithm = "RSA";
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
			Cipher test = Cipher.getInstance(cAlgorithm);
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

	/* -------------------- KEYS OPERATIONS -------------------- */
	public String getSignature( String text )
	{
		if(keyLoaded)
		{
			try
			{
				Signature dsa = Signature.getInstance(sAlgorithm);
				dsa.initSign( privateKey );
				dsa.update( text.getBytes() );
				byte[] signature = dsa.sign();
				return getString( signature );
			}
			catch( Exception e ){e.printStackTrace();}
		}
		return null;
	}

	public boolean verifySignature( String plaintext, String signature )
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

	/**
	 * Returns true if the specified text is encrypted, false otherwise
	 */
	public static boolean isEncrypted( String text )
	{
		// If the string does not have any separators then it is not
		// encrypted
		if( text.indexOf( '-' ) == -1 )
		{
			///System.out.println( "text is not encrypted: no dashes" );
			return false;
		}

		StringTokenizer st = new StringTokenizer( text, "-", false );
		while( st.hasMoreTokens() )
		{
			String token = st.nextToken();
			if( token.length() > 3 )
			{
				return false;
			}
			for( int i=0; i<token.length(); i++ )
			{
				if( !Character.isDigit( token.charAt( i ) ) )
				{
					return false;
				}
			}
		}
		//System.out.println( "text is encrypted" );
		return true;
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
	}

	// GETTER / SETTER
	public PrivateKey getPrivateKey() { return privateKey; }
	//public void setPrivateKey(PrivateKey privateKey) { this.privateKey = privateKey; }
	public PublicKey getPublicKey() { return publicKey; }
	//public void setPublicKey(PublicKey publicKey) { this.publicKey = publicKey; }
	public boolean isKeyLoaded() { return keyLoaded; }
	//public void setKeyLoaded(boolean keyLoaded) { this.keyLoaded = keyLoaded; }

	/*public static void test(HelloAndroid ha)
	{
		PKI pki = new PKI();
		pki.generateKeys();
		String data = "This is a test";
		String baddata = "This is an test";
		String signature = pki.sign( data );
		String badSignature = signature.substring( 0, signature.length() - 1 ) + "1";
		boolean verifies = pki.verifySignature( data, signature );
		boolean verifiesBad = pki.verifySignature( data, badSignature );
		boolean verifiesBad2 = pki.verifySignature( baddata, signature );

		ha.print( "Texte: " + data );
		ha.print( "Mauvais texte: " + baddata );
		ha.print( "Signature du texte: " + signature );
		ha.print( "Verification texte-signature (true): " + verifies );
		ha.print( "Fausse signature: " + badSignature );
		ha.print( "Verification texte-fausse signature (false): " + verifiesBad );
		ha.print( "Verification faux texte-signature (false): " + verifiesBad2 );
	}*/
}
