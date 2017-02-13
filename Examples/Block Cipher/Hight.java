/**
 * Class Hight implements Hong et al.'s HIGHT block cipher.
 *
 * @author  Alan Kaminsky
 * @version 02-Mar-2016
 */
public class Hight
	implements BlockCipher
	{

	// Table of round constants.
	private static byte[] RC = new byte [128];
	static
		{
		int s = 0x5a;
		for (int i = 0; i <= 127; ++ i)
			{
			RC[i] = (byte) s;
			s = (((s << 3) ^ (s << 6)) & 0x40) | (s >>> 1);
			}
		}

	// Number of rounds.
	private int R;

	// Whitening keys and subkeys.
	private byte[] WK = new byte [8];
	private byte[] SK = new byte [128];

	/**
	 * Construct a new HIGHT block cipher object. The cipher uses the full
	 * number of rounds (32).
	 */
	public Hight()
		{
		this (32);
		}

	/**
	 * Construct a new HIGHT block cipher object with the given number of
	 * rounds.
	 *
	 * @param  R  Number of rounds (1 .. 32).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>R</TT> is not in the range 1 ..
	 *     32.
	 */
	public Hight
		(int R)
		{
		if (1 > R || R > 32)
			throw new IllegalArgumentException (String.format
				("Hight(): R = %d illegal", R));
		this.R = R;
		}

	/**
	 * Returns this block cipher's block size in bytes.
	 * <P>
	 * For class Hight, the block size is 64 bits (8 bytes).
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
	 * For class Hight, the key size is 128 bits (16 bytes).
	 *
	 * @return  Key size.
	 */
	public int keySize()
		{
		return 16;
		}

	/**
	 * Returns the number of rounds in this block cipher.
	 * <P>
	 * For class Hight, the number of rounds is 32.
	 *
	 * @return  Number of rounds.
	 */
	public int numRounds()
		{
		return 32;
		}

	/**
	 * Set the key for this block cipher. <TT>key</TT> must be an array of bytes
	 * whose length is equal to <TT>keySize()</TT>.
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
			throw new IllegalArgumentException
				("Hight.setKey(): key must be 16 bytes");

		// Set up whitening keys.
		System.arraycopy (key, 12, WK, 0, 4);
		System.arraycopy (key,  0, WK, 4, 4);

		// Set up subkeys.
		for (int i = 0; i <= 7; ++ i)
			{
			for (int j = 0; j <= 7; ++ j)
				SK[16*i+j] = (byte) (key[(j-i+8)%8] + RC[16*i+j]);
			for (int j = 0; j <= 7; ++ j)
				SK[16*i+j+8] = (byte) (key[(j-i+8)%8+8] + RC[16*i+j+8]);
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
		if (text.length != 8)
			throw new IllegalArgumentException
				("Hight.encrypt(): text must be 8 bytes");

		// Initial transformation.
		text[0] += WK[0];
		text[2] ^= WK[1];
		text[4] += WK[2];
		text[6] ^= WK[3];

		// Do R rounds (1 .. 32).
		for (int i = 0; i <= R - 2; ++ i)
			{
			feistel (text, i);
			rotateLeft (text);
			}
		feistel (text, R - 1);

		// Final transformation.
		text[0] += WK[4];
		text[2] ^= WK[5];
		text[4] += WK[6];
		text[6] ^= WK[7];
		}

	/**
	 * Apply the Feistel functions to the given text for round i.
	 */
	private void feistel
		(byte[] text,
		 int i)
		{
		text[7] ^= F_0(text[6]) + SK[4*i+3];
		text[1] += F_1(text[0]) ^ SK[4*i+2];
		text[3] ^= F_0(text[2]) + SK[4*i+1];
		text[5] += F_1(text[4]) ^ SK[4*i];
		}

	/**
	 * Feistel function F_0(x).
	 */
	private byte F_0
		(byte x)
		{
		return (byte)
			(((x << 1) | (x >>> 7)) ^
			 ((x << 2) | (x >>> 6)) ^
			 ((x << 7) | (x >>> 1)));
		}

	/**
	 * Feistel function F_1(x).
	 */
	private byte F_1
		(byte x)
		{
		return (byte)
			(((x << 3) | (x >>> 5)) ^
			 ((x << 4) | (x >>> 4)) ^
			 ((x << 6) | (x >>> 2)));
		}

	/**
	 * Rotate the given text left by one byte.
	 */
	private void rotateLeft
		(byte[] text)
		{
		byte t = text[7];
		System.arraycopy (text, 0, text, 1, 7);
		text[0] = t;
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
				("Hight.decrypt(): text must be 8 bytes");

		// Inverse final transformation.
		text[0] -= WK[4];
		text[2] ^= WK[5];
		text[4] -= WK[6];
		text[6] ^= WK[7];

		// Do R inverse rounds (1 .. 32).
		invFeistel (text, R - 1);
		for (int i = R - 2; i >= 0; -- i)
			{
			rotateRight (text);
			invFeistel (text, i);
			}

		// Inverse initial transformation.
		text[0] -= WK[0];
		text[2] ^= WK[1];
		text[4] -= WK[2];
		text[6] ^= WK[3];
		}

	/**
	 * Apply the Feistel functions to the given text for round i in the inverse
	 * direction.
	 */
	private void invFeistel
		(byte[] text,
		 int i)
		{
		text[7] ^= F_0(text[6]) + SK[4*i+3];
		text[1] -= F_1(text[0]) ^ SK[4*i+2];
		text[3] ^= F_0(text[2]) + SK[4*i+1];
		text[5] -= F_1(text[4]) ^ SK[4*i];
		}

	/**
	 * Rotate the given text right by one byte.
	 */
	private void rotateRight
		(byte[] text)
		{
		byte t = text[0];
		System.arraycopy (text, 1, text, 0, 7);
		text[7] = t;
		}

	}
