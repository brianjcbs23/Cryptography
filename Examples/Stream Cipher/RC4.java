/**
 * Class RC4 implements Rivest's RC4 stream cipher.
 *
 * @author  Alan Kaminsky
 * @version 02-Mar-2016
 */
public class RC4
    implements StreamCipher
    {
    private byte[] S = new byte [256];
    private int x;
    private int y;

    /**
     * Returns this stream cipher's key size in bytes. If the stream cipher
     * includes both a key and a nonce, <TT>keySize()</TT> returns the size of
     * the key plus the size of the nonce in bytes.
     * <P>
     * For class RC4, the key size is fixed at 16 bytes.
     *
     * @return  Key size.
     */
    public int keySize()
        {
        return 16;
        }

    /**
     * Set the key for this stream cipher. <TT>key</TT> must be an array of
     * bytes whose length is equal to <TT>keySize()</TT>. If the stream cipher
     * includes both a key and a nonce, <TT>key</TT> contains the bytes of the
     * key followed by the bytes of the nonce. The keystream generator is
     * initialized, such that successive calls to <TT>encrypt()</TT> or
     * <TT>decrypt()</TT> will encrypt or decrypt a series of bytes.
     * <P>
     * For class RC4, bytes <TT>key[0]</TT> through <TT>key[15]</TT> are used.
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
        if (key.length != 16)
            throw new IllegalArgumentException("RC4.setKey(): key must be 16 bytes");

        for (int i = 0; i <= 255; ++ i)
            S[i] = (byte)i;
        int j = 0;
        for (int i = 0; i <= 255; ++ i)
            {
            j = (j + S[i] + key[i & 15]) & 255;
            swap (i, j);
            }
        x = 0;
        y = 0;
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
        x = (x + 1) & 255;
        y = (y + S[x]) & 255;
        swap (x, y);
        return (S[(S[x] + S[y]) & 255] ^ b) & 255;
        }

    /**
     * Swap S[i] with S[j].
     */
    private void swap
        (int i,
         int j)
        {
        byte t = S[i];
        S[i] = S[j];
        S[j] = t;
        }
    }