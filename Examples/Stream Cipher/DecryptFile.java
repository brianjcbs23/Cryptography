import edu.rit.util.Hex;
import edu.rit.util.Instance;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Class DecryptFile is a unit test main program for a stream cipher class that
 * decrypts a ciphertext file. The file's contents are replaced with the
 * plaintext.
 * <P>
 * Usage: <TT>java DecryptFile <I>cipherClass</I> <I>key</I> <I>file</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 03-Feb-2016
 */
public class DecryptFile
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
        File file = new File (args[2]);

        // Create an instance of the stream cipher class.
        StreamCipher cipher = (StreamCipher)
            Instance.newInstance (cipherClass+"()");

        // Verify preconditions.
        if (key.length != cipher.keySize())
            error (String.format ("Key must be %d bytes", cipher.keySize()));

        // Read ciphertext from file and decrypt.
        cipher.setKey (key);
        FileInputStream fin = new FileInputStream (file);
        ByteArrayOutputStream pt = new ByteArrayOutputStream();
        int b;
        while ((b = fin.read()) != -1)
            pt.write (cipher.decrypt (b));
        fin.close();

        // Write plaintext back into file.
        FileOutputStream fout = new FileOutputStream (file);
        pt.writeTo (fout);
        fout.close();
        }

    /**
     * Print the given error message and exit.
     *
     * @param  msg  Error message.
     */
    private static void error
        (String msg)
        {
        System.err.printf ("DecryptFile: %s%n", msg);
        usage();
        }

    /**
     * Print a usage message and exit.
     */
    private static void usage()
        {
        System.err.println ("Usage: java DecryptFile <cipherClass> <key> <file>");
        System.err.println ("<cipherClass> = StreamCipher class name");
        System.err.println ("<key> = Key (hexadecimal)");
        System.err.println ("<file> = File name");
        System.exit (1);
        }
    }