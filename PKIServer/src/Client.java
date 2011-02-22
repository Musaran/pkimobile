import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Key;
import java.security.KeyFactory;
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

	public void run()
	{
		try	{
			byte[] read = new byte[65534];
			int nb = fromClient.read(read);
			System.out.println(" [*] Recu "+nb+" bytes");//: [0]"+read[0]+" [H]"+read.hashCode());
			byte[] rec = new byte[nb];
			//String l = "";
			for(int i=0; i < nb; i++) {
				rec[i] = read[i];
				//l += rec[i]+"/";
			}
			//System.out.println("Refac: [0]"+rec[0]+" [H]"+rec.hashCode());
			//System.out.println(l);
			
			byte[] decrypted = decryptText(rec, parent.getPrivateKey());
			
			// DEBUG
			// ----------------------------------
			/*System.out.println("Decrypted: ");
			String l = "";
			for(int i=0; i < 20; i++) {
				l += decrypted[i]+"/";
			}
			System.out.println(l);*/
			// ----------------------------------
			
			if(decrypted[0] == 1)
			{
				System.out.println("[0x01] Tentative de connexion");
				
				try {
					if(parent.isFileExists("client.pub"))
					{
						KeyFactory keyFactory = KeyFactory.getInstance("RSA");
						X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(parent.getFile("client.pub"));
						PublicKey clp  = keyFactory.generatePublic(publicKeySpec);
						System.out.println("[0x01] Cle chargee");
						
						byte[] message = "CHALLENGE".getBytes();
						byte[] rcvmsg = new byte[message.length];
						System.arraycopy(decrypted, 1, rcvmsg, 0, message.length); // BOF inside
						if(Arrays.equals(message, rcvmsg))
						{
							System.out.println("[0x01] Challenge recu. Verification de la signature...");
							int signlgth = (decrypted.length - (message.length + 1));
							byte[] sign = new byte[signlgth];
							System.arraycopy(decrypted, (1+message.length), sign, 0, signlgth);
							boolean res = verifySignature(clp, message, sign);
							if(res)
							{
								System.out.println("[0x01] Signature CORRECTE !");
								System.out.println("[0x01] ('''''''========= WIN =========='''''')");
								byte[] ret = {1};
								this.send(ret);
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
				try {
					System.out.println("[0x02] Reception de la cle publique...");
					byte[] publickey = new byte[decrypted.length-1];
					System.arraycopy(decrypted, 1, publickey, 0, decrypted.length-1);
					KeyFactory keyFactory = KeyFactory.getInstance("RSA");
					X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publickey);
					PublicKey clp  = keyFactory.generatePublic(publicKeySpec);
					System.out.println("[0x02] Cle publique recue");
					
					// DEBUG
					// ----------------------------------
					/*System.out.println("[0x02] Cle recue : ");
					String l = "";
					for(int i=0; i < 20; i++) {
						l += publickey[i]+"/";
					}
					System.out.println(l);*/
					// ----------------------------------
					
					parent.setFile("client.pub", clp.getEncoded());
					
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

	public void send( byte[] msg )
	{
		try {
			toClient.write(msg);
		} catch (IOException e) { e.printStackTrace(); }
	}

	public void stop()
	{
		try	{
			client.close();
			System.out.println( " [*] Client deconnecte.");
		} catch(IOException e){e.printStackTrace();}
	}
	
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
	
	/* ---------------- PKI -------------------- */
	public byte[] decryptText( byte[] btext, Key pri )
	{
		try
		{
			DataOutputStream eOutRSA = new DataOutputStream(new FileOutputStream("temp.m"));
			Cipher cf = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cf.init(Cipher.DECRYPT_MODE, pri);
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
				
				byte[] decodedMsg = cf.doFinal(te);
				eOutRSA.write(decodedMsg, 0, decodedMsg.length);
			}*/
			cf.update(btext);
			byte[] decodedMsg = cf.doFinal();
			eOutRSA.write(decodedMsg, 0, decodedMsg.length);
			/* --- */
			eOutRSA.close();
			byte[] res = parent.getFile("temp.m");
			File f = new File("temp.m");
			f.delete();
			return res;
		}
		catch( Exception e ){e.printStackTrace();}
		return null;
	}
	
	public boolean verifySignature( PublicKey pub, byte[] msg, byte[] sign )
	{
		try {
			Signature rsa = Signature.getInstance("SHA1withRSA");
			rsa.initVerify( pub );
			rsa.update( msg );
			boolean res = rsa.verify( sign );
			return res;
		}catch( Exception e ){e.printStackTrace();}
		return false;
	}
}
