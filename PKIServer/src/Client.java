import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.Key;
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
		
		System.out.println( "Client connecte.");
		new Thread( this ).start();
	}

	public void run()
	{
		try	{
			byte[] read = new byte[65534];
			int nb = fromClient.read(read);
			System.out.println("Recu "+nb+" bytes: [0]"+read[0]+" [H]"+read.hashCode());
			byte[] rec = new byte[nb];
			//String l = "";
			for(int i=0; i < nb; i++) {
				rec[i] = read[i];
				//l += rec[i]+"/";
			}
			System.out.println("Refac: [0]"+rec[0]+" [H]"+rec.hashCode());
			//System.out.println(l);
			
			byte[] decrypted = decryptText(rec, parent.getPrivateKey());
			
			// DEBUG
			System.out.println("Decrypted: ");
			String l = "";
			for(int i=0; i < 20; i++) {
				l += decrypted[i]+"/";
			}
			System.out.println(l);
			
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
			System.out.println( "Client deconnecte.");
		} catch(IOException e){e.printStackTrace();}
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
}
