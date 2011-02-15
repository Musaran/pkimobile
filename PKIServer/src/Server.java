import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

public class Server implements Runnable
{
	private PrivateKey privateKey = null;
	private ServerSocket sServeur;
	
	public static void main(String[] args)
	{
		@SuppressWarnings("unused")
		Server s = new Server(1023);
	}
	
	public Server( int iPort )
	{
		try
		{
			// On recupere notre cle privee, du serveur.
			URL url = new URL("http://williamjouot.com/pki/private.der");
			URLConnection connection = url.openConnection();
			InputStream input = connection.getInputStream();
			FileOutputStream writeFile = new FileOutputStream("temp.der");
			byte[] buffer = new byte[1024];
			int read;
			while ((read = input.read(buffer)) > 0)
				writeFile.write(buffer, 0, read);
			writeFile.flush();
			
			// On la charge
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(getFile("temp.der"));
			this.privateKey = keyFactory.generatePrivate(privateKeySpec);
			
			// On lance le serveur
			System.out.println( "Demarrage du serveur [port: " + iPort + "]..." );
			sServeur = new ServerSocket( iPort );
			new Thread( this ).start();
		}
		catch (Exception e) {e.printStackTrace();}
	}
	
	public void run()
	{
		System.out.println( "Demarrage de l'ecoute..." );
		try
		{
			for (;;)
			{
				new Client( sServeur.accept(), this );
			}
		} 
		catch( Exception e ) { e.printStackTrace(); }
	}
	
	public PrivateKey getPrivateKey()
	{
		return privateKey;
	}
	
	public byte[] getFile(String filename)
	{
		try
		{
			FileInputStream fis = new FileInputStream(filename);
			byte[] encodedFile = new byte[fis.available()];
			fis.read(encodedFile);
			fis.close();
			return encodedFile;
		}
		catch (Exception e) {e.printStackTrace();}
		return null;
	}
}
