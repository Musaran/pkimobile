import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;

class Client implements Runnable
{
	private Socket client;
	private DataInputStream fromClient;
	private DataOutputStream toClient;
	private Server parent;

	/**
	 * Create and manage a new client connection (the mobile)
	 * @param client	the socket of the client
	 * @param s			the pointer to the server
	 */
	public Client( Socket client, Server s )
	{
		this.client = client;
		this.parent = s;
		
		try {
			fromClient = new DataInputStream(client.getInputStream());
			toClient = new DataOutputStream(client.getOutputStream());
		} catch (IOException e) { try { client.close(); } catch (IOException ee) {}	}
		
		System.out.println( " [*] --------------------------------");
		System.out.println( " [*] Client connecte");
		new Thread( this ).start();
	}

	/**
	 * Look for receive message and answer
	 */
	public void run()
	{
		try	{
			// We receive a message...
			// So we decrypte it
			byte[] read = new byte[65534];
			int nb = fromClient.read(read);
			System.out.println(" [*] Recu "+nb+" bytes");
			byte[] rec = new byte[nb];
			for(int i=0; i < nb; i++) {	rec[i] = read[i]; }
			
			byte[] decrypted = decryptText(rec, parent.getPrivateKey());
			
			// If the first byte is 1 then it's a connexion attempt
			if(decrypted[0] == 1)
			{
				System.out.println("[0x01] Tentative de connexion");
				
				try {
					if(parent.isFileExists("client.pub"))
					{
						// We load the public key of the client
						KeyFactory keyFactory = KeyFactory.getInstance("RSA");
						X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(parent.getFile("client.pub"));
						PublicKey clp  = keyFactory.generatePublic(publicKeySpec);
						System.out.println("[0x01] Cle chargee");
						
						// We verify if the message start by "CHALLENGE"
						byte[] message = "CHALLENGE".getBytes();
						byte[] rcvmsg = new byte[message.length];
						System.arraycopy(decrypted, 1, rcvmsg, 0, message.length); // BOF inside
						if(Arrays.equals(message, rcvmsg))
						{
							// Yep, so we check the signature
							System.out.println("[0x01] Challenge recu. Verification de la signature...");
							int signlgth = (decrypted.length - (message.length + 1));
							byte[] sign = new byte[signlgth];
							System.arraycopy(decrypted, (1+message.length), sign, 0, signlgth);
							boolean res = verifySignature( message, sign, clp );
							if(res)
							{
								// Everything is OK
								System.out.println("[0x01] Signature CORRECTE !");
								System.out.println("[0x01] ('''''''========= WIN =========='''''')");
								
								// We send the crypted response
								byte[] ret = "AUTH".getBytes();
								byte[] retsign = getSignature(ret, parent.getPrivateKey());
								byte[] msgfinal = new byte[ret.length + retsign.length];
								System.arraycopy(ret, 0, msgfinal, 0, ret.length);
								System.arraycopy(retsign, 0, msgfinal, ret.length, retsign.length);
								this.send(encryptText(msgfinal, parent.getPublicKey()));
							}
							else
							{
								System.out.println("[0x01] Mauvaise signature. Renvoi 2");
								byte[] ret = {2};
								this.send(ret);
							}
						}
						else
							System.out.println("[0x01] Mauvais CHALLENGE.");
					}
					else
						System.out.println("[0x01] Pas de cle publique du client.");
				}
				catch(Exception e)
				{
					e.printStackTrace();
					System.out.println("[0x01] Envoi reponse 2");
					byte[] res = {2};
					this.send(res);
				}
			}
			else if(decrypted[0] == 2)
			{
				// First byte is 2, so we receive a public key encrypted with our private key
				try {
					// Extract and create the public key
					System.out.println("[0x02] Reception de la cle publique...");
					byte[] publickey = new byte[decrypted.length-1];
					System.arraycopy(decrypted, 1, publickey, 0, decrypted.length-1);
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publickey);
					PublicKey clp  = keyFactory.generatePublic(publicKeySpec);
					System.out.println("[0x02] Cle publique recue");
					
					// Put it in a file
					parent.setFile("client.pub", clp.getEncoded());
					
					// Send the OK response
					System.out.println("[0x02] Envoi reponse 1");
					byte[] res = {1};
					this.send(res);
				}
				catch(Exception e)
				{
					e.printStackTrace();
					System.out.println("[0x02] Envoi reponse 2");
					byte[] res = {2};
					this.send(res);
				}
			}
			else
				System.out.println("[?x??] Message inconnu.");
			
		}catch (IOException e){	e.printStackTrace(); }
		
		stop();
	}

	/**
	 * Send a message to the client
	 * @param msg	the message to send
	 */
	public void send( byte[] msg )
	{
		try {
			toClient.write(msg);
		} catch (IOException e) { e.printStackTrace(); }
	}

	/**
	 * Stop the connexion and disconnect the client
	 */
	public void stop()
	{
		try	{
			client.close();
			System.out.println( " [*] Client deconnecte.");
		} catch(IOException e){e.printStackTrace();}
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
	/* ---------------------------------      PKI       --------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/**
	 * Encrypt a text
	 * @param text	the text which must be crypted
	 * @param pub	the public key
	 * @return		the crypted text
	 */
	public byte[] encryptText( byte[] text, PublicKey pub )
	{
		try
		{
			DataOutputStream eOutRSA = new DataOutputStream(new FileOutputStream("temp.m"));
			Cipher cf = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cf.init(Cipher.ENCRYPT_MODE, pub);
			cf.update(text);
			byte[] encodedMsg = cf.doFinal();
			eOutRSA.write(encodedMsg, 0, encodedMsg.length);
			eOutRSA.close();
			byte[] res = parent.getFile("temp.m");
			parent.deleteFile("temp.m");
			return res;
		}
		catch( Exception e ){e.printStackTrace();}
		return null;
	}
	
	/**
	 * Decrypt a message with a private key.
	 * @param text	the text to decrypt
	 * @param pri	the private key used to decrypt
	 * @return		the text decrypted
	 */
	public byte[] decryptText( byte[] text, PrivateKey pri )
	{
		try
		{
			DataOutputStream eOutRSA = new DataOutputStream(new FileOutputStream("temp.m"));
			Cipher cf = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cf.init(Cipher.DECRYPT_MODE, pri);
			cf.update(text);
			byte[] decodedMsg = cf.doFinal();
			eOutRSA.write(decodedMsg, 0, decodedMsg.length);
			eOutRSA.close();
			byte[] res = parent.getFile("temp.m");
			parent.deleteFile("temp.m");
			return res;
		}
		catch( Exception e ){e.printStackTrace();}
		return null;
	}
	
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
}
