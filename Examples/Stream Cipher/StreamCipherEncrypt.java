import edu.rit.util.Hex;
import edu.rit.util.Instance;

/**
 * Class StreamCipherEncrypt is a unit test main program for a stream cipher
 * class that encrypts a plaintext.
 * <P>
 * Usage: <TT>java StreamCipherEncrypt <I>cipherClass</I> <I>key</I>
 * <I>plaintext</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 29-Jan-2016
 */
public class StreamCipherEncrypt
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
        byte[] plaintext = Hex.toByteArray (args[2]);

        // Create an instance of the stream cipher class.
        StreamCipher cipher = (StreamCipher)
            Instance.newInstance (cipherClass+"()");

        // Verify preconditions.
        if (key.length != cipher.keySize())
            error (String.format ("Key must be %d bytes, key is %d bytes", cipher.keySize(), key.length));

        // Print plaintext.
        for (int i = 0; i < plaintext.length; ++ i)
            System.out.printf ("%02x", plaintext[i]);
        System.out.println();

        // Encrypt plaintext with key.
        cipher.setKey (key);
        for (int i = 0; i < plaintext.length; ++ i)
            System.out.printf ("%02x", cipher.encrypt (plaintext[i]));
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
        System.err.printf ("StreamCipherEncrypt: %s%n", msg);
        usage();
        }

    /**
     * Print a usage message and exit.
     */
    private static void usage()
        {
        System.err.println ("Usage: java StreamCipherEncrypt <cipherClass> <key> <plaintext>");
        System.err.println ("<cipherClass> = StreamCipher class name");
        System.err.println ("<key> = Key (hexadecimal)");
        System.err.println ("<plaintext> = Plaintext (hexadecimal)");
        System.exit (1);
        }
    }