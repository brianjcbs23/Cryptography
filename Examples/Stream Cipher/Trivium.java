import edu.rit.numeric.BigInteger;

/**
 * Class Trivium implements De Canniere's and Preneel's Trivium stream cipher.
 *
 * @author  Alan Kaminsky
 * @version 06-Apr-2016
 */
public class Trivium
    implements StreamCipher
    {
    private static final BigInteger mask80 = new BigInteger (160).assignHex("ffffffffffffffffffff");

    private BigInteger r = new BigInteger (288);  // Shift register
    private BigInteger kn = new BigInteger (160); // Key and nonce

    /**
     * Returns this stream cipher's key size in bytes. If the stream cipher
     * includes both a key and a nonce, <TT>keySize()</TT> returns the size of
     * the key plus the nonce in bytes.
     * <P>
     * For class Trivium, the key size is 80 bits (10 bytes) and the nonce size
     * is 80 bits (10 bytes).
     *
     * @return  Key size.
     */
    public int keySize()
        {
        return 20;
        }

    /**
     * Set the key for this stream cipher. <TT>key</TT> must be an array of
     * bytes whose length is equal to <TT>keySize()</TT>. If the stream cipher
     * includes both a key and a nonce, <TT>key</TT> contains the bytes of the
     * key followed by the bytes of the nonce. The keystream generator is
     * initialized, such that successive calls to <TT>encrypt()</TT> or
     * <TT>decrypt()</TT> will encrypt or decrypt a series of bytes.
     * <P>
     * The <TT>key</TT> argument contains the 80-bit key (<TT>key[0..9]</TT>,
     * 10 bytes) followed by the 80-bit nonce (<TT>key[10..19]</TT>, 10 bytes).
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
        if (key.length != 20)
            throw new IllegalArgumentException("Trivium.setKey(): key must be 20 bytes");
//                (Trivium.setKey(): key must be 20 bytes);

        // kn = key in msbs, nonce in lsbs.
        kn.packBigEndian (key);

        // r = nonce in proper bit positions.
        r.assign (kn) .and (mask80) .leftShift (93);

        // kn = nonce in msbs, key in lsbs.
        kn.rightRotate (80);

        // r = nonce and key in proper bit positions.
        r.or (kn.and (mask80));

        // Set register's 3 msbs to 1.
        r.setBit (285) .setBit (286) .setBit (287);

        // Clock register to establish initial state.
        for (int i = 0; i < 1152; ++ i)
            clock();
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
        int ks = 0;
        for (int i = 0; i <= 7; ++ i)
            ks |= clock() << i;
        return ks ^ (b & 255);
        }

    /**
     * Clock the register.
     *
     * @return  Keystream bit, 0 or 1.
     */
    private int clock()
        {
        int t1 = r.getBit (65) ^ r.getBit (92);
        int t2 = r.getBit (161) ^ r.getBit (176);
        int t3 = r.getBit (242) ^ r.getBit (287);
        int z = t1 ^ t2 ^ t3;
        t1 = t1 ^ (r.getBit (90) & r.getBit (91)) ^ r.getBit (170);
        t2 = t2 ^ (r.getBit (174) & r.getBit (175)) ^ r.getBit (263);
        t3 = t3 ^ (r.getBit (285) & r.getBit (286)) ^ r.getBit (68);
        r.leftShift (1) .putBit (0, t3) .putBit (93, t1) .putBit (177, t2);
        return z;
        }
    }