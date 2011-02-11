import java.net.ServerSocket;

public class Server implements Runnable
{
	public static void main(String[] args) {
		@SuppressWarnings("unused")
		Server s = new Server(1023);
	}
	
	private ServerSocket sServeur;
	
	public Server( int iPort )
	{
		System.out.println( "Demarrage du serveur [port: " + iPort + "]..." );
		try {
			sServeur = new ServerSocket( iPort );
		} catch( Exception e ) { e.printStackTrace(); }
		new Thread( this ).start();
	}
	
	public void run()
	{
		System.out.println( "Demarrage de l'ecoute..." );
		try
		{
			for (;;)
			{
				new Client( sServeur.accept() );
			}
		} 
		catch( Exception e ) { e.printStackTrace(); }
	}
}
