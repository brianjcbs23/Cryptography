import edu.rit.util.Hex;
import edu.rit.util.Instance;

/**
 * Class BlockCipherEncrypt is a unit test main program for a block cipher class
 * that encrypts a plaintext block.
 * <P>
 * Usage: <TT>java BlockCipherEncrypt <I>cipherClass</I> <I>key</I>
 * <I>plaintext</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 29-Jan-2016
 */
public class BlockCipherEncrypt
	{
	/**
	 * Main program.
	 */
	public static void main
		(String[] args)
		throws Exception
		{
		// Parse command line arguments.
		if (args.length != 3) usage();
		String cipherClass = args[0];
		byte[] key = Hex.toByteArray (args[1]);
		byte[] text = Hex.toByteArray (args[2]);

		// Create an instance of the block cipher class.
		BlockCipher cipher = (BlockCipher)
			Instance.newInstance (cipherClass+"()");

		// Verify preconditions.
		if (key.length != cipher.keySize())
			error (String.format ("Key must be %d bytes", cipher.keySize()));
		if (text.length != cipher.blockSize())
			error (String.format ("Plaintext must be %d bytes",
				cipher.blockSize()));

		// Print plaintext.
		for (int i = 0; i < text.length; ++ i)
			System.out.printf ("%02x", text[i]);
		System.out.println();

		// Encrypt plaintext with key.
		cipher.setKey (key);
		cipher.encrypt (text);
		for (int i = 0; i < text.length; ++ i)
			System.out.printf ("%02x", text[i]);
		System.out.println();
		}

	/**
	 * Print the given error message and exit.
	 *
	 * @param  msg  Error message.
	 */
	private static void error
		(String msg)
		{
		System.err.printf ("BlockCipherEncrypt: %s%n", msg);
		usage();
		}

	/**
	 * Print a usage message and exit.
	 */
	private static void usage()
		{
		System.err.println ("Usage: java BlockCipherEncrypt <cipherClass> <key> <plaintext>");
		System.err.println ("<cipherClass> = BlockCipher class name");
		System.err.println ("<key> = Key (hexadecimal)");
		System.err.println ("<plaintext> = Plaintext (hexadecimal)");
		System.exit (1);
		}
	}
