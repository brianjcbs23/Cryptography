import edu.rit.util.Hex;
import edu.rit.util.Instance;

/**
 * Class StreamCipherDecrypt is a unit test main program for a stream cipher
 * class that decrypts a ciphertext.
 * <P>
 * Usage: <TT>java StreamCipherDecrypt <I>cipherClass</I> <I>key</I>
 * <I>ciphertext</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 29-Jan-2016
 */
public class StreamCipherDecrypt
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
        byte[] ciphertext = Hex.toByteArray (args[2]);

        // Create an instance of the stream cipher class.
        StreamCipher cipher = (StreamCipher)
            Instance.newInstance (cipherClass+"()");

        // Verify preconditions.
        if (key.length != cipher.keySize())
            error (String.format ("Key must be %d bytes", cipher.keySize()));

        // Print ciphertext.
        for (int i = 0; i < ciphertext.length; ++ i)
            System.out.printf ("%02x", ciphertext[i]);
        System.out.println();

        // Decrypt ciphertext with key.
        cipher.setKey (key);
        for (int i = 0; i < ciphertext.length; ++ i)
            System.out.printf ("%02x", cipher.decrypt (ciphertext[i]));
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
        System.err.printf ("StreamCipherDecrypt: %s%n", msg);
        usage();
        }

    /**
     * Print a usage message and exit.
     */
    private static void usage()
        {
        System.err.println ("Usage: java StreamCipherDecrypt <cipherClass> <key> <ciphertext>");
        System.err.println ("<cipherClass> = StreamCipher class name");
        System.err.println ("<key> = Key (hexadecimal)");
        System.err.println ("<ciphertext> = Ciphertext (hexadecimal)");
        System.exit (1);
        }
    }