import edu.rit.util.Hex;
import edu.rit.util.Instance;

/**
 * Class BlockCipherDecrypt is a unit test main program for a block cipher class
 * that decrypts a ciphertext block.
 * <P>
 * Usage: <TT>java BlockCipherDecrypt <I>cipherClass</I> <I>key</I>
 * <I>ciphertext</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 29-Jan-2016
 */
public class BlockCipherDecrypt
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

		// Print ciphertext.
		for (int i = 0; i < text.length; ++ i)
			System.out.printf ("%02x", text[i]);
		System.out.println();

		// Decrypt ciphertext with key.
		cipher.setKey (key);
		cipher.decrypt (text);
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
		System.err.printf ("BlockCipherDecrypt: %s%n", msg);
		usage();
		}

	/**
	 * Print a usage message and exit.
	 */
	private static void usage()
		{
		System.err.println ("Usage: java BlockCipherDecrypt <cipherClass> <key> <ciphertext>");
		System.err.println ("<cipherClass> = BlockCipher class name");
		System.err.println ("<key> = Key (hexadecimal)");
		System.err.println ("<ciphertext> = Ciphertext (hexadecimal)");
		System.exit (1);
		}
	}
