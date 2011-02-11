import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

class Client implements Runnable
{
	private Socket client;
	private DataInputStream fromClient;
	private DataOutputStream toClient;

	public Client( Socket client )
	{
		this.client = client;
		
		try {
			fromClient = new DataInputStream(client.getInputStream());
			toClient = new DataOutputStream(client.getOutputStream());
		} catch (IOException e) { try { client.close(); } catch (IOException ee) {}	}
		
		System.out.println( "Client connecté.");
		new Thread( this ).start();
	}

	@SuppressWarnings("null")
	public void run()
	{
		try	{
			/*while(( fromClient.readFully(read) ) != null )
			{
				
				//traitementReception( lue );
			}*/
			byte[] read = null;
			fromClient.readFully(read);
			System.out.println("Recu "+read.toString());
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
			System.out.println( "Client deconnecté.");
		} catch(IOException e){e.printStackTrace();}
	}   
}
