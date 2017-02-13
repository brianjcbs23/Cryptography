import edu.rit.util.Packing;

/**
 * Class Threefish256 implements Ferguson et al.'s Threefish-256 block cipher.
 *
 * @author  Alan Kaminsky
 * @version 02-Mar-2016
 */
public class Threefish256
	implements BlockCipher
	{
	// Number of rounds.
	private int R;

	private long[][] subkey = new long [19] [4];
	private long[] block = new long [4];

	/**
	 * Construct a new Threefish-256 block cipher object. The cipher uses the
	 * full number of rounds (18).
	 */
	public Threefish256()
		{
		this (18);
		}

	/**
	 * Construct a new Threefish-256 block cipher object with the given number
	 * of rounds.
	 *
	 * @param  R  Number of rounds (1 .. 18).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>R</TT> is not in the range 1 ..
	 *     18.
	 */
	public Threefish256
		(int R)
		{
		if (1 > R || R > 18)
			throw new IllegalArgumentException (String.format
				("Threefish256(): R = %d illegal", R));
		this.R = R;
		}

	/**
	 * Returns this block cipher's block size in bytes.
	 * <P>
	 * For class Threefish256, the block size is 256 bits (32 bytes).
	 *
	 * @return  Block size.
	 */
	public int blockSize()
		{
		return 32;
		}

	/**
	 * Returns this block cipher's key size in bytes.
	 * <P>
	 * For class Threefish256, the key size is 256 bits (32 bytes) and the tweak
	 * size is 128 bits (16 bytes).
	 *
	 * @return  Key size.
	 */
	public int keySize()
		{
		return 48;
		}

	/**
	 * Returns the number of rounds in this block cipher.
	 * <P>
	 * For class Threefish256, the number of rounds is 18. Each round consists
	 * of one subkey addition layer and four mix-permutation layers.
	 *
	 * @return  Number of rounds.
	 */
	public int numRounds()
		{
		return 18;
		}

	/**
	 * Set the key for this block cipher. <TT>key</TT> must be an array of bytes
	 * whose length is equal to <TT>keySize()</TT>.
	 * <P>
	 * The <TT>key</TT> argument contains the 256-bit key (<TT>key[0..31]</TT>,
	 * 32 bytes) followed by the 128-bit tweak (<TT>key[32..47]</TT>, 16 bytes).
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
		if (key.length != 48)
			throw new IllegalArgumentException
				("Threefish256.setKey(): key must be 48 bytes");

		long[] k = new long [5];
		Packing.packLongLittleEndian (key, 0, k, 0, 4);
		k[4] = 0x1BD11BDAA9FC1A22L ^ k[0] ^ k[1] ^ k[2] ^ k[3];

		long[] t = new long [3];
		Packing.packLongLittleEndian (key, 32, t, 0, 2);
		t[2] = t[0] ^ t[1];

		for (int s = 0; s <= 18; ++ s)
			{
			subkey[s][0] = k[s % 5];
			subkey[s][1] = k[(s + 1) % 5] + t[s % 3];
			subkey[s][2] = k[(s + 2) % 5] + t[(s + 1) % 3];
			subkey[s][3] = k[(s + 3) % 5] + s;
			}
		}

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
		if (text.length != 32)
			throw new IllegalArgumentException
				("Threefish256.encrypt(): text must be 32 bytes");

		Packing.packLongLittleEndian (text, 0, block, 0, 4);

		for (int s = 0; s <= R - 1; s += 2)
			round (s);
		addSubkey (R);

		Packing.unpackLongLittleEndian (block, 0, text, 0, 4);
		}

	/**
	 * Perform the round function for subkeys s and s + 1.
	 */
	private void round
		(int s)
		{
		addSubkey (s);
		mix (0, 1, 14); mix (2, 3, 16);
		mix (0, 3, 52); mix (2, 1, 57);
		mix (0, 1, 23); mix (2, 3, 40);
		mix (0, 3,  5); mix (2, 1, 37);
		addSubkey (s + 1);
		mix (0, 1, 25); mix (2, 3, 33);
		mix (0, 3, 46); mix (2, 1, 12);
		mix (0, 1, 58); mix (2, 3, 22);
		mix (0, 3, 32); mix (2, 1, 32);
		}

	/**
	 * Add subkey s to the block.
	 */
	private void addSubkey
		(int s)
		{
		block[0] += subkey[s][0];
		block[1] += subkey[s][1];
		block[2] += subkey[s][2];
		block[3] += subkey[s][3];
		}

	/**
	 * Perform the MIX operation on block words a and b with the given rotation.
	 */
	private void mix
		(int a,
		 int b,
		 int rotate)
		{
		block[a] += block[b];
		block[b] = block[a] ^ Long.rotateLeft (block[b], rotate);
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
		if (text.length != 32)
			throw new IllegalArgumentException
				("Threefish256.decrypt(): text must be 32 bytes");

		Packing.packLongLittleEndian (text, 0, block, 0, 4);

		subtractSubkey (R);
		for (int s = R - 1; s >= 0; s -= 2)
			inverseRound (s);

		Packing.unpackLongLittleEndian (block, 0, text, 0, 4);
		}

	/**
	 * Perform the inverse round function for subkeys s and s - 1.
	 */
	private void inverseRound
		(int s)
		{
		inverseMix (0, 3, 32); inverseMix (2, 1, 32);
		inverseMix (0, 1, 58); inverseMix (2, 3, 22);
		inverseMix (0, 3, 46); inverseMix (2, 1, 12);
		inverseMix (0, 1, 25); inverseMix (2, 3, 33);
		subtractSubkey (s);
		inverseMix (0, 3,  5); inverseMix (2, 1, 37);
		inverseMix (0, 1, 23); inverseMix (2, 3, 40);
		inverseMix (0, 3, 52); inverseMix (2, 1, 57);
		inverseMix (0, 1, 14); inverseMix (2, 3, 16);
		subtractSubkey (s - 1);
		}

	/**
	 * Subtract subkey s from the block.
	 */
	private void subtractSubkey
		(int s)
		{
		block[0] -= subkey[s][0];
		block[1] -= subkey[s][1];
		block[2] -= subkey[s][2];
		block[3] -= subkey[s][3];
		}

	/**
	 * Perform the inverse MIX operation on block words a and b with the given
	 * rotation.
	 */
	private void inverseMix
		(int a,
		 int b,
		 int rotate)
		{
		block[b] = Long.rotateRight (block[a] ^ block[b], rotate);
		block[a] -= block[b];
		}

	}
