package com.hw;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class ServerDialog
{
	private Socket sk;
	//private PrintStream versServeur;
	//private BufferedReader depuisServeur;
	private boolean isConnected = false;
	
	private DataInputStream fromServer;
	private DataOutputStream toServer;
	
	private void disconnect()
	{
		if(isConnected)
		{
			isConnected = false;
			try	{
				sk.close();
			} catch ( Exception e ){e.printStackTrace();}
		}
	}
	
	private void connect( String ip, int port )
	{
		try
		{
			sk = new Socket( ip, port );
			//versServeur = new PrintStream(new DataOutputStream(sk.getOutputStream()) );
			//depuisServeur = new BufferedReader(new InputStreamReader(sk.getInputStream()));
			fromServer = new DataInputStream(sk.getInputStream());
			toServer = new DataOutputStream(sk.getOutputStream());
			isConnected = true;
		}
		catch( Exception e ){e.printStackTrace(); isConnected = false;}
	}
	
	private void send( byte[] message )
	{
		if(isConnected)
		{
			try {
				//versServeur.write(message); //versServeur.print( message );
				toServer.write(message);
				//toServer.flush();
				
			} catch (IOException e) {e.printStackTrace();}
		}
	}
	
	private byte[] receive( int timeout )
	{
		if(isConnected)
		{
			boolean ok = true;
			long now = System.currentTimeMillis();
			
			
			while( ok )
			{
				timeout = timeout * 1000;
				if( ( System.currentTimeMillis() - now ) >= timeout )
				{
					ok = false;
				}
				else
				{
					try
					{
						byte[] res = new byte[65534];
						int nb = fromServer.read(res);
						byte[] ret = new byte[nb];
						for(int i=0; i < nb; i++) {	ret[i] = res[i]; }
						return ret;
					}
					catch( Exception e ){e.printStackTrace();}
				}
			}
		}
		return null;
	}
	
	public byte[] getFromServer(String ip, int port, byte[] msg)
	{
		connect(ip, port);
		send(msg);
		byte[] res = receive(5);
		disconnect();
		return res;
	}
}
