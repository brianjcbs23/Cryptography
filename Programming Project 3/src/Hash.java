import edu.rit.util.Hex;
import edu.rit.util.Instance;

/**
 * Class Hash is a unit test main program for a hash function class that
 * computes the digest of a message.
 * <P>
 * Usage: <TT>java Hash <I>hashClass</I> <I>message</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 06-Apr-2016
 */
public class Hash
	{
	/**
	 * Main program.
	 */
	public static void main
		(String[] args)
		throws Exception
		{
		// Parse command line arguments.
		if (args.length != 2) usage();
		String hashClass = args[0];
		byte[] message = Hex.toByteArray (args[1]);

		// Create an instance of the hash function class.
		HashFunction hasher = (HashFunction)
			Instance.newInstance (hashClass+"()");

		// Compute and print digest of message.
		byte[] d = new byte [hasher.digestSize()];
		hasher.append (message);
		hasher.digest (d);
		for (int i = 0; i < d.length; ++ i)
			System.out.printf ("%02x", d[i]);
		System.out.println();
		}

	/**
	 * Print a usage message and exit.
	 */
	private static void usage()
		{
		System.err.println ("Usage: java Hash <hashClass> <message>");
		System.err.println ("<hashClass> = HashFunction class name");
		System.err.println ("<message> = Message (hexadecimal)");
		System.exit (1);
		}
	}
