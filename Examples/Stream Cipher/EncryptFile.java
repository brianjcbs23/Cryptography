import edu.rit.util.Hex;
import edu.rit.util.Instance;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

/**
 * Class EncryptFile is a unit test main program for a stream cipher class that
 * encrypts a plaintext file. The file's contents are replaced with the
 * ciphertext.
 * <P>
 * Usage: <TT>java EncryptFile <I>cipherClass</I> <I>key</I> <I>file</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 03-Feb-2016
 */
public class EncryptFile
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

        // Read plaintext from file and encrypt.
        cipher.setKey (key);
        FileInputStream fin = new FileInputStream (file);
        ByteArrayOutputStream ct = new ByteArrayOutputStream();
        int b;
        while ((b = fin.read()) != -1)
            ct.write (cipher.encrypt (b));
        fin.close();

        // Write ciphertext back into file.
        FileOutputStream fout = new FileOutputStream (file);
        ct.writeTo (fout);
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
        System.err.printf ("EncryptFile: %s%n", msg);
        usage();
        }

    /**
     * Print a usage message and exit.
     */
    private static void usage()
        {
        System.err.println ("Usage: java EncryptFile <cipherClass> <key> <file>");
        System.err.println ("<cipherClass> = StreamCipher class name");
        System.err.println ("<key> = Key (hexadecimal)");
        System.err.println ("<file> = File name");
        System.exit (1);
        }
    }