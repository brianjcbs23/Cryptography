import edu.rit.numeric.BigInteger;
import edu.rit.util.Hex;
import edu.rit.util.Packing;

/**
 * Class Present80 implements Bogdanov et al.'s PRESENT-80 block cipher.
 *
 * @author  Alan Kaminsky
 * @version 06-Apr-2016
 */
public class Present80
	implements BlockCipher
	{
	// Number of rounds.
	private int R;

	private long[] subkey = new long [32];

	/**
	 * Construct a new PRESENT-80 block cipher object. The cipher uses the full
	 * number of rounds (31).
	 */
	public Present80()
		{
		this (31);
		}

	/**
	 * Construct a new PRESENT-80 block cipher object with the given number of
	 * rounds.
	 *
	 * @param  R  Number of rounds (1 .. 31).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>R</TT> is not in the range 1 ..
	 *     31.
	 */
	public Present80
		(int R)
		{
		if (1 > R || R > 31)
			throw new IllegalArgumentException (String.format
				("Present80(): R = %d illegal", R));
		this.R = R;
		}

	/**
	 * Returns this block cipher's block size in bytes.
	 * <P>
	 * For class Present80, the block size is 64 bits (8 bytes).
	 *
	 * @return  Block size.
	 */
	public int blockSize()
		{
		return 8;
		}

	/**
	 * Returns this block cipher's key size in bytes.
	 * <P>
	 * For class Present80, the key size is 80 bits (10 bytes).
	 *
	 * @return  Key size.
	 */
	public int keySize()
		{
		return 10;
		}

	/**
	 * Returns the number of rounds in this block cipher.
	 * <P>
	 * For class Present80, the number of rounds is 31.
	 *
	 * @return  Number of rounds.
	 */
	public int numRounds()
		{
		return 31;
		}

	/**
	 * Set the key for this block cipher. <TT>key</TT> must be an array of bytes
	 * whose length is equal to <TT>keySize()</TT>.
	 * <P>
	 * The <TT>key</TT> argument contains the 80-bit key (<TT>key[0..9]</TT>,
	 * 10 bytes).
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
		if (key.length != 10)
			throw new IllegalArgumentException
				("Present80.setKey(): key must be 10 bytes");

		BigInteger K = new BigInteger (80) .packBigEndian (key);
		BigInteger tmp = new BigInteger (80);

		subkey[0] = tmp.assign (K) .rightShift (16) .longValue();
		for (int r = 1; r <= 31; ++ r)
			{
			K.leftRotate (61);
			tmp.assign (S[tmp.assign (K) .rightShift (76) .intValue()]);
			K.and (KEYMASK) .or (tmp.leftShift (76));
			K.xor (r << 15);
			subkey[r] = tmp.assign (K) .rightShift (16) .longValue();
			}
		}

	private static final BigInteger KEYMASK =
		new BigInteger (80) .assignHex ("0fffffffffffffffffff");

	/**
	 * Encrypt the given plaintext. <TT>text</TT> must be an array of bytes
	 * whose length is equal to <TT>blockSize()</TT>. On input, <TT>text</TT>
	 * contains the plaintext block. The plaintext block is encrypted using the
	 * key specified in the most recent call to <TT>setKey()</TT>. On output,
	 * <TT>text</TT> contains the ciphertext block.
	 *
	 * @param  text  Plaintext (on input), ciphertext (on output).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>text.length</TT> &ne;
	 *     <TT>blockSize()</TT>.
	 */
	public void encrypt
		(byte[] text)
		{
		if (text.length != 8)
			throw new IllegalArgumentException
				("Present80.encrypt(): text must be 8 bytes");

		long data = Packing.packLongBigEndian (text, 0);
		long t;

		// Subkey addition (round 0).
		data ^= subkey[0];

		// Do R rounds (1 .. 31).
		for (int r = 1; r <= R; ++ r)
			{
			// S-box layer.
			t = 0;
			for (int i = 0; i < 64; i += 4)
				t |= S[(int)(data >>> i) & 15] << i;

			// Bit permutation layer.
			data = 0;
			for (int i = 0; i < 64; ++ i)
				data |= ((t >>> i) & 1) << P[i];

			// Subkey addition.
			data ^= subkey[r];
			}

		Packing.unpackLongBigEndian (data, text, 0);
		}

	/**
	 * Decrypt the given plaintext. <TT>text</TT> must be an array of bytes
	 * whose length is equal to <TT>blockSize()</TT>. On input, <TT>text</TT>
	 * contains the ciphertext block. The ciphertext block is decrypted using
	 * the key specified in the most recent call to <TT>setKey()</TT>. On
	 * output, <TT>text</TT> contains the plaintext block.
	 *
	 * @param  text  Ciphertext (on input), plaintext (on output).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>text.length</TT> &ne;
	 *     <TT>blockSize()</TT>.
	 */
	public void decrypt
		(byte[] text)
		{
		if (text.length != 8)
			throw new IllegalArgumentException
				("Present80.decrypt(): text must be 8 bytes");

		long data = Packing.packLongBigEndian (text, 0);
		long t;

		// Do R inverse rounds (1 .. 31).
		for (int r = R; r >= 1; -- r)
			{
			// Subkey addition.
			data ^= subkey[r];

			// Inverse bit permutation layer.
			t = 0;
			for (int i = 0; i < 64; ++ i)
				t |= ((data >>> i) & 1) << invP[i];

			// Inverse S-box layer.
			data = 0;
			for (int i = 0; i < 64; i += 4)
				data |= invS[(int)(t >>> i) & 15] << i;
			}

		// Subkey addition (round 0).
		data ^= subkey[0];

		Packing.unpackLongBigEndian (data, text, 0);
		}

	/**
	 * The PRESENT S-box.
	 */
	private static final long[] S = new long[]
		{ 12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2 };

	/**
	 * The PRESENT inverse S-box.
	 */
	private static final long[] invS = new long [16];
	static
		{
		for (int i = 0; i <= 15; ++ i)
			invS[(int)S[i]] = i;
		}

	/**
	 * The PRESENT bit permutation.
	 */
	private static final int[] P = new int [64];
	static
		{
		for (int i = 0; i <= 62; ++ i)
			P[i] = (16*i) % 63;
		P[63] = 63;
		}

	/**
	 * The PRESENT inverse bit permutation.
	 */
	private static final int[] invP = new int [64];
	static
		{
		for (int i = 0; i <= 63; ++ i)
			invP[P[i]] = i;
		}

	/**
	 * Unit test main program. Prints test vectors from the PRESENT spec.
	 */
	public static void main
		(String[] args)
		{
		testVector
			(/*key*/ "00000000000000000000",
			 /*pt */ "0000000000000000",
			 /*ct */ "5579c1387b228445");
		testVector
			(/*key*/ "ffffffffffffffffffff",
			 /*pt */ "0000000000000000",
			 /*ct */ "e72c46c0f5945049");
		testVector
			(/*key*/ "00000000000000000000",
			 /*pt */ "ffffffffffffffff",
			 /*ct */ "a112ffc72f68417b");
		testVector
			(/*key*/ "ffffffffffffffffffff",
			 /*pt */ "ffffffffffffffff",
			 /*ct */ "3333dcd3213210d2");
		}

	/**
	 * Compute one test vector.
	 */
	private static void testVector
		(String key,
		 String pt,
		 String ct)
		{
		System.out.printf ("*** Test Vector ***%n");
		System.out.printf ("%s = key%n", key);
		System.out.printf ("%s = original plaintext%n", pt);
		Present80 cipher = new Present80();
		cipher.setKey (Hex.toByteArray (key));
		byte[] text = Hex.toByteArray (pt);
		cipher.encrypt (text);
		System.out.printf ("%s = encrypted ciphertext%n", Hex.toString (text));
		System.out.printf ("%s = correct ciphertext%n", ct);
		cipher.decrypt (text);
		System.out.printf ("%s = decrypted plaintext%n", Hex.toString (text));
		System.out.printf ("%s = original plaintext%n", pt);
		}
	}
