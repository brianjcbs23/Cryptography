import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Class Salsa20 implements Bernstein's Salsa20 stream cipher.
 *
 * @author  Alan Kaminsky
 * @version 02-Mar-2016
 */
public class Salsa20
    implements StreamCipher
    {
    private int[] x = new int [16];
    private long counter;
    private int[] z = new int [16];
    private byte[] keystream = new byte [64];
    private int ksb = 64;

    /**
     * Returns this stream cipher's key size in bytes. If the stream cipher
     * includes both a key and a nonce, <TT>keySize()</TT> returns the size of
     * the key plus the size of the nonce in bytes.
     * <P>
     * For class Salsa20, the key size is 128 bits (16 bytes) and the nonce size
     * is 64 bits (8 bytes).
     *
     * @return  Key size.
     */
    public int keySize()
        {
        return 24;
        }

    /**
     * Set the key for this stream cipher. <TT>key</TT> must be an array of
     * bytes whose length is equal to <TT>keySize()</TT>. If the stream cipher
     * includes both a key and a nonce, <TT>key</TT> contains the bytes of the
     * key followed by the bytes of the nonce. The keystream generator is
     * initialized, such that successive calls to <TT>encrypt()</TT> or
     * <TT>decrypt()</TT> will encrypt or decrypt a series of bytes.
     * <P>
     * The <TT>key</TT> argument contains the 128-bit key (<TT>key[0..15]</TT>,
     * 16 bytes) followed by the 64-bit nonce (<TT>key[16..23]</TT>, 8 bytes).
     *
     * @param  key  Key.
     *
     * @exception  IllegalArgumentException
     *     (unchecked exception) Thrown if <TT>key.length</TT> &ne;
     *     <TT>keySize()</TT>.
     */
    public void setKey
        (byte[] key)
        {
        if (key.length != 24)
            throw new IllegalArgumentException("Salsa20.setKey(): key must be 24 bytes");

        x[0] = 0x61707865;
        x[5] = 0x3120646e;
        x[10] = 0x79622d36;
        x[15] = 0x6b206574;
        Packing.packIntLittleEndian (key, 0, x, 1, 4);
        Packing.packIntLittleEndian (key, 0, x, 11, 4);
        Packing.packIntLittleEndian (key, 16, x, 6, 2);
        counter = 0;
        }

    /**
     * Encrypt the given byte. Only the least significant 8 bits of <TT>b</TT>
     * are used. The ciphertext byte is returned as a value from 0 to 255.
     *
     * @param  b  Plaintext byte.
     *
     * @return  Ciphertext byte.
     */
    public int encrypt
        (int b)
        {
        return encryptOrDecrypt (b);
        }

    /**
     * Decrypt the given byte. Only the least significant 8 bits of <TT>b</TT>
     * are used. The plaintext byte is returned as a value from 0 to 255.
     *
     * @param  b  Ciphertext byte.
     *
     * @return  Plaintext byte.
     */
    public int decrypt
        (int b)
        {
        return encryptOrDecrypt (b);
        }

    /**
     * Encrypt or decrypt the given byte. Only the least significant 8 bits of
     * <TT>b</TT> are used. If <TT>b</TT> is a plaintext byte, the ciphertext
     * byte is returned as a value from 0 to 255. If <TT>b</TT> is a ciphertext
     * byte, the plaintext byte is returned as a value from 0 to 255.
     *
     * @param  b  Plaintext byte (if encrypting), ciphertext byte (if
     *            decrypting).
     *
     * @return  Ciphertext byte (if encrypting), plaintext byte (if decrypting).
     */
    private int encryptOrDecrypt
        (int b)
        {
        if (ksb == 64)
            generateKeystream();
        return (b ^ keystream[ksb++]) & 255;
        }

    /**
     * Generate the next keystream block.
     */
    private void generateKeystream()
        {
        Packing.unpackLongLittleEndian (counter, x, 8);
        ++ counter;
        System.arraycopy (x, 0, z, 0, 16);
        for (int round = 1; round <= 10; ++ round)
            {
            quarterround (0,  4,  8,  12);
            quarterround (5,  9,  13, 1 );
            quarterround (10, 14, 2,  6 );
            quarterround (15, 3,  7,  11);
            quarterround (0,  1,  2,  3 );
            quarterround (5,  6,  7,  4 );
            quarterround (10, 11, 8,  9 );
            quarterround (15, 12, 13, 14);
            }
        for (int i = 0; i <= 15; ++ i)
            {
            z[i] += x[i];
            }
        Packing.unpackIntLittleEndian (z, 0, keystream, 0, 16);
        ksb = 0;
        }

    /**
     * Perform the quarterround operation on the z array.
     */
    private void quarterround
        (int a, int b, int c, int d)
        {
        z[b] ^= Integer.rotateLeft (z[a] + z[d], 7);
        z[c] ^= Integer.rotateLeft (z[a] + z[b], 9);
        z[d] ^= Integer.rotateLeft (z[b] + z[c], 13);
        z[a] ^= Integer.rotateLeft (z[c] + z[d], 18);
        }

    /**
     * Unit test main program. Computes the last test vector on page 8 of the
     * Salsa20 specification.
     */
    public static void main
        (String[] args)
        {
        Salsa20 cipher = new Salsa20();
        cipher.setKey (Hex.toByteArray ("0102030405060708090a0b0c0d0e0f1065666768696a6b6c"));
        System.out.printf ("Before:%n");
        printState (cipher.x);
        cipher.counter = 0x74737271706f6e6dL;
        cipher.generateKeystream();
        System.out.printf ("After:%n");
        printState (cipher.z);
        }

    private static void printState
        (int[] state)
        {
        for (int i = 0; i <= 3; ++ i)
            {
            for (int j = 0; j <= 3; ++j)
                printWord (state[4*i+j]);
            System.out.println();
            }
        }

    private static void printWord
        (int w)
        {
        System.out.printf ("%4d", (w      ) & 255);
        System.out.printf ("%4d", (w >>  8) & 255);
        System.out.printf ("%4d", (w >> 16) & 255);
        System.out.printf ("%4d", (w >> 24) & 255);
        }
    }