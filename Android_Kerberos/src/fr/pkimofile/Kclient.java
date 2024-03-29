package fr.pkimofile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.Properties;
import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

public class Kclient
{
	/**
	 * <p>Client logs in to a Key Distribution Center (KDC) using JAAS and then
	 * requests a service ticket for the server, base 64 encodes it and writes it
	 * to the file <i>service-ticket.txt</i>.</p>
	 * <p>This class, in combination with the <i>Server</i> class illustrates the
	 * use of the JAAS and GSS APIs for initiating a security context using the
	 * Kerberos protocol.</p>
	 * <p>This requires a KDC/domain controller such as Active Directory or Apache
	 * Directory. The KDC configuration details are stored in the
	 * <i>client.properties</i> file, while the JAAS details are stored in the
	 * file <i>jaas.conf</i>.</p>
	 * @author Ants
	 */

	public static void main( String[] args) {
		try {
			// Setup up the Kerberos properties.
			Properties props = new Properties();
			
			File f = new File( "/client.properties" );
			System.out.println( f.getAbsolutePath() ) ;
			
			props.load( new FileInputStream( f ));
			System.setProperty( "sun.security.krb5.debug", "true");
			System.setProperty( "java.security.krb5.realm", props.getProperty( "realm")); 
			System.setProperty( "java.security.krb5.kdc", props.getProperty( "kdc"));
			System.setProperty( "java.security.auth.login.config", "E:/jaas.conf");
			System.setProperty( "javax.security.auth.useSubjectCredsOnly", "true");
			String username = props.getProperty( "client.principal.name");
			String password = props.getProperty( "client.password");
			
			// Oid mechanism = use Kerberos V5 as the security mechanism.
			krb5Oid = new Oid( "1.2.840.113554.1.2.2");
			Kclient client = new Kclient();
			// Login to the KDC.
			client.login( username, password);
			// Request the service ticket.
			client.initiateSecurityContext( props.getProperty( "service.principal.name"));
			// Write the ticket to disk for the server to read.
			encodeAndWriteTicketToDisk( client.serviceTicket, "./security.token");
			System.out.println( "Service ticket encoded to disk successfully");
		}
		catch ( LoginException e) {
			e.printStackTrace();
			System.err.println( "There was an error during the JAAS login");
			System.exit( -1);
		}
		catch ( GSSException e) {
			e.printStackTrace();
			System.err.println( "There was an error during the security context initiation");
			System.exit( -1);
		}
		catch ( IOException e) {
			e.printStackTrace();
			System.err.println( "There was an IO error");
			System.exit( -1);
		}
	}

	private static Oid krb5Oid;

	private Subject subject;
	private byte[] serviceTicket;

	// Authenticate against the KDC using JAAS.
	private void login( String username, String password) throws LoginException {
		LoginContext loginCtx = null;
		// "Client" references the JAAS configuration in the jaas.conf file.
		loginCtx = new LoginContext( "Client", new LoginCallbackHandler( username, password));
		loginCtx.login();
		this.subject = loginCtx.getSubject();
	}

	// Begin the initiation of a security context with the target service.
	private void initiateSecurityContext( String servicePrincipalName) throws GSSException
	{
		GSSManager manager = GSSManager.getInstance();
		GSSName serverName = manager.createName( servicePrincipalName, GSSName.NT_USER_NAME);// HOSTBASED
		final GSSContext context = manager.createContext( serverName, krb5Oid, null, GSSContext.DEFAULT_LIFETIME);
		// The GSS context initiation has to be performed as a privileged action.
		this.serviceTicket = Subject.doAs( subject, new PrivilegedAction<byte[]>() {
			public byte[] run() {
				try {
					byte[] token = new byte[0];
					// This is a one pass context initialisation.
					context.requestMutualAuth( false);
					context.requestCredDeleg( false);
					return context.initSecContext( token, 0, token.length);
				}
				catch ( GSSException e) {
					e.printStackTrace();
					return null;
				}
			}
		});

	}

	// Base64 encode the raw ticket and write it to the given file.
	private static void encodeAndWriteTicketToDisk( byte[] ticket, String filepath)	throws IOException
	{
		FileWriter writer = new FileWriter( new File( filepath));
		writer.write( new String(ticket) );
		writer.close();
	}
}
