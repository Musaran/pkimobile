import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Server implements Runnable
{
	private PrivateKey privateKey = null;
	private PublicKey publicKey = null;
	private ServerSocket sServeur;
	
	public static void main(String[] args)
	{
		@SuppressWarnings("unused")
		Server s = new Server(1023);
	}
	
	/**
	 * Create a new listening server
	 * @param iPort	the port to listen
	 */
	public Server( int iPort )
	{
		try
		{
			System.out.println(" [*] Recuperation des cles du serveur...");

			// On charge notre cle privee et publique
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(getURL("http://williamjouot.com/pki/private.der"));
			this.privateKey = keyFactory.generatePrivate(privateKeySpec);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(getURL("http://williamjouot.com/pki/public"));
			this.publicKey  = keyFactory.generatePublic(publicKeySpec);
			
			// On lance le serveur
			System.out.println( " [*] Demarrage du serveur [port: " + iPort + "]..." );
			sServeur = new ServerSocket( iPort );
			new Thread( this ).start();
		}
		catch (Exception e) {e.printStackTrace();}
	}
	
	/**
	 * The thread which listen
	 */
	public void run()
	{
		System.out.println( " [*] Demarrage de l'ecoute..." );
		try
		{
			for (;;)
			{
				new Client( sServeur.accept(), this );
			}
		} 
		catch( Exception e ) { e.printStackTrace(); }
	}
	
	/**
	 * Return the private key of the server
	 * @return the private key of the server
	 */
	public PrivateKey getPrivateKey()
	{
		return privateKey;
	}
	
	/**
	 * Return the public key of the server
	 * @return the public key of the server
	 */
	public PublicKey getPublicKey()
	{
		return publicKey;
	}
	
	/**
	 * Return the array of bytes from an URL
	 * @param link	the url
	 * @return an array of bytes
	 */
	public byte[] getURL(String link)
	{
		try {
			URL url = new URL(link);
			URLConnection connection = url.openConnection();
			InputStream input = connection.getInputStream();
			FileOutputStream writeFile = new FileOutputStream("temp.der");
			byte[] buffer = new byte[1024];
			int read;
			while ((read = input.read(buffer)) > 0)
				writeFile.write(buffer, 0, read);
			writeFile.flush();
			return getFile("temp.der");
		}
		catch(Exception e){ e.printStackTrace(); }
		return null;
	}
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------    FICHIERS    --------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/* ---------------------------------------------------------------------------------- */
	/**
	 * Return true if a file exists
	 * @param filename	the file to test
	 * @return true if it exists
	 */
	public boolean isFileExists(String filename)
	{
		File f = new File(filename);
		return f.exists();
	}
	
	/**
	 * Get the array of bytes from a specified file
	 * @param filename	the file to read
	 * @return the array of bytes in the file
	 */
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
	
	/**
	 * Write an array of bytes in a file
	 * @param filename	the file to write into
	 * @param content	the content to write
	 */
	public void setFile(String filename, byte[] content)
	{
		try
		{
			FileOutputStream fis = new FileOutputStream(filename);
			fis.write(content);
			fis.close();
		}
		catch (Exception e) {e.printStackTrace();}
	}

	/**
	 * Delete a file
	 * @param string the file to delete
	 */
	public void deleteFile(String filename)
	{
		File f = new File(filename);
		f.delete();
	}
}
