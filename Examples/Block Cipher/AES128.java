import edu.rit.util.Hex;

/**
 * Class AES128 implements the NIST standard AES block cipher with a 128-bit
 * key.
 *
 * @author  Alan Kaminsky
 * @version 02-Mar-2016
 */
public class AES128
	implements BlockCipher
	{
	// The AES 4x4-element state matrix is coded as a 16-element Java array in
	// column major order, like so:
	//   s00  s01  s02  s03  --->  s[0]  s[4]  s[ 8]  s[12]
	//   s10  s11  s12  s13  --->  s[1]  s[5]  s[ 9]  s[13]
	//   s20  s21  s22  s23  --->  s[2]  s[6]  s[10]  s[14]
	//   s30  s31  s32  s33  --->  s[3]  s[7]  s[11]  s[15]

	// Number of rounds.
	private int R;

	// Array of subkeys, indexed by round.
	byte[][] subkey = new byte [11] [16];

	/**
	 * Construct a new AES-128 block cipher object. The cipher uses the full
	 * number of rounds (10).
	 */
	public AES128()
		{
		this (10);
		}

	/**
	 * Construct a new AES-128 block cipher object with the given number of
	 * rounds.
	 *
	 * @param  R  Number of rounds (1 .. 10).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>R</TT> is not in the range 1 ..
	 *     10.
	 */
	public AES128
		(int R)
		{
		if (1 > R || R > 10)
			throw new IllegalArgumentException (String.format
				("AES128(): R = %d illegal", R));
		this.R = R;
		}

	/**
	 * Returns this block cipher's block size in bytes.
	 * <P>
	 * For class AES128, the block size is 128 bits (16 bytes).
	 *
	 * @return  Block size.
	 */
	public int blockSize()
		{
		return 16;
		}

	/**
	 * Returns this block cipher's key size in bytes.
	 * <P>
	 * For class AES128, the key size is 128 bits (16 bytes).
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
	 * For class AES128, the number of rounds is 10.
	 *
	 * @return  Number of rounds.
	 */
	public int numRounds()
		{
		return 10;
		}

	/**
	 * Set the key for this block cipher. <TT>key</TT> must be an array of bytes
	 * whose length is equal to <TT>keySize()</TT>.
	 * <P>
	 * The <TT>key</TT> argument contains the 128-bit key (<TT>key[0..15]</TT>,
	 * 16 bytes).
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
				("AES128.setKey(): key must be 16 bytes");

		// Initialize key matrix.
		int k00 = key[ 0] & 255;
		int k10 = key[ 1] & 255;
		int k20 = key[ 2] & 255;
		int k30 = key[ 3] & 255;
		int k01 = key[ 4] & 255;
		int k11 = key[ 5] & 255;
		int k21 = key[ 6] & 255;
		int k31 = key[ 7] & 255;
		int k02 = key[ 8] & 255;
		int k12 = key[ 9] & 255;
		int k22 = key[10] & 255;
		int k32 = key[11] & 255;
		int k03 = key[12] & 255;
		int k13 = key[13] & 255;
		int k23 = key[14] & 255;
		int k33 = key[15] & 255;
		int rcon = 1;

		// Store initial (round 0) subkey.
		System.arraycopy (key, 0, subkey[0], 0, 16);

		// Compute subkeys for rounds 1 through 10.
		for (int r = 1; r <= 10; ++ r)
			{
			// Update column 0 of round subkey.
			k00 ^= (sbox[k13] ^ rcon) & 255;
			k10 ^= sbox[k23] & 255;
			k20 ^= sbox[k33] & 255;
			k30 ^= sbox[k03] & 255;
			rcon = times (2, rcon);

			// Update column 1 of round subkey.
			k01 ^= k00;
			k11 ^= k10;
			k21 ^= k20;
			k31 ^= k30;

			// Update column 2 of round subkey.
			k02 ^= k01;
			k12 ^= k11;
			k22 ^= k21;
			k32 ^= k31;

			// Update column 3 of round subkey.
			k03 ^= k02;
			k13 ^= k12;
			k23 ^= k22;
			k33 ^= k32;

			// Store round subkey.
			subkey[r][ 0] = (byte) k00;
			subkey[r][ 1] = (byte) k10;
			subkey[r][ 2] = (byte) k20;
			subkey[r][ 3] = (byte) k30;
			subkey[r][ 4] = (byte) k01;
			subkey[r][ 5] = (byte) k11;
			subkey[r][ 6] = (byte) k21;
			subkey[r][ 7] = (byte) k31;
			subkey[r][ 8] = (byte) k02;
			subkey[r][ 9] = (byte) k12;
			subkey[r][10] = (byte) k22;
			subkey[r][11] = (byte) k32;
			subkey[r][12] = (byte) k03;
			subkey[r][13] = (byte) k13;
			subkey[r][14] = (byte) k23;
			subkey[r][15] = (byte) k33;
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
		if (text.length != 16)
			throw new IllegalArgumentException
				("AES128.encrypt(): text must be 16 bytes");

		addRoundKey (text, subkey[0]);
		for (int r = 1; r <= R - 1; ++ r)
			{
			subBytes (text);
			shiftRows (text);
			mixColumns (text);
			addRoundKey (text, subkey[r]);
			}
		subBytes (text);
		shiftRows (text);
		addRoundKey (text, subkey[R]);
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
		if (text.length != 16)
			throw new IllegalArgumentException
				("AES128.decrypt(): text must be 16 bytes");

		addRoundKey (text, subkey[R]);
		invShiftRows (text);
		invSubBytes (text);
		for (int r = R - 1; r >= 1; -- r)
			{
			addRoundKey (text, subkey[r]);
			invMixColumns (text);
			invShiftRows (text);
			invSubBytes (text);
			}
		addRoundKey (text, subkey[0]);
		}

	/**
	 * Perform the AddRoundKey operation on the given state.
	 */
	private static void addRoundKey
		(byte[] state,
		 byte[] subkey)
		{
		for (int i = 0; i <= 15; ++ i)
			state[i] ^= subkey[i];
		}

	/**
	 * Perform the SubBytes operation on the given state.
	 */
	private static void subBytes
		(byte[] state)
		{
		for (int i = 0; i <= 15; ++ i)
			state[i] = sbox[state[i]&255];
		}

	/**
	 * Perform the ShiftRows operation on the given state.
	 */
	private static void shiftRows
		(byte[] state)
		{
		byte t;

		// Row 1
		t = state[1];
		state[1] = state[5];
		state[5] = state[9];
		state[9] = state[13];
		state[13] = t;

		// Row 2
		t = state[2];
		state[2] = state[10];
		state[10] = t;
		t = state[6];
		state[6] = state[14];
		state[14] = t;

		// Row 3
		t = state[15];
		state[15] = state[11];
		state[11] = state[7];
		state[7] = state[3];
		state[3] = t;
		}

	/**
	 * Perform the MixColumns operation on the given state.
	 */
	private static void mixColumns
		(byte[] state)
		{
		mixOneColumn (state,  0,  1,  2,  3);
		mixOneColumn (state,  4,  5,  6,  7);
		mixOneColumn (state,  8,  9, 10, 11);
		mixOneColumn (state, 12, 13, 14, 15);
		}

	/**
	 * Mix the given column of the given state.
	 */
	private static void mixOneColumn
		(byte[] state,
		 int a,
		 int b,
		 int c,
		 int d)
		{
		int s_a = state[a] & 255;
		int s_b = state[b] & 255;
		int s_c = state[c] & 255;
		int s_d = state[d] & 255;
		state[a] = (byte)(times (2, s_a) ^ times (3, s_b) ^ s_c ^ s_d);
		state[b] = (byte)(s_a ^ times (2, s_b) ^ times (3, s_c) ^ s_d);
		state[c] = (byte)(s_a ^ s_b ^ times (2, s_c) ^ times (3, s_d));
		state[d] = (byte)(times (3, s_a) ^ s_b ^ s_c ^ times (2, s_d));
		}

	/**
	 * Compute the GF(2^8) product of the given quantities using the irreducible
	 * polynomial x^8 + x^4 + x^3 + x + 1.
	 */
	private static int times
		(int a,
		 int b)
		{
		int c = 0;
		for (int bit = 0x80; bit > 0; bit >>= 1)
			{
			c <<= 1;
			if ((c & 0x100) != 0) c ^= 0x11b;
			if ((b & bit) != 0) c ^= a;
			}
		return c;
		}

	/**
	 * Perform the inverse SubBytes operation on the given state.
	 */
	private static void invSubBytes
		(byte[] state)
		{
		for (int i = 0; i <= 15; ++ i)
			state[i] = invSbox[state[i]&255];
		}

	/**
	 * Perform the inverse ShiftRows operation on the given state.
	 */
	private static void invShiftRows
		(byte[] state)
		{
		byte t;

		// Row 1
		t = state[13];
		state[13] = state[9];
		state[9] = state[5];
		state[5] = state[1];
		state[1] = t;

		// Row 2
		t = state[2];
		state[2] = state[10];
		state[10] = t;
		t = state[6];
		state[6] = state[14];
		state[14] = t;

		// Row 3
		t = state[3];
		state[3] = state[7];
		state[7] = state[11];
		state[11] = state[15];
		state[15] = t;
		}

	/**
	 * Perform the inverse MixColumns operation on the given state.
	 */
	private static void invMixColumns
		(byte[] state)
		{
		invMixOneColumn (state,  0,  1,  2,  3);
		invMixOneColumn (state,  4,  5,  6,  7);
		invMixOneColumn (state,  8,  9, 10, 11);
		invMixOneColumn (state, 12, 13, 14, 15);
		}

	/**
	 * Inverse-mix the given column of the given state.
	 */
	private static void invMixOneColumn
		(byte[] state,
		 int a,
		 int b,
		 int c,
		 int d)
		{
		int s_a = state[a] & 255;
		int s_b = state[b] & 255;
		int s_c = state[c] & 255;
		int s_d = state[d] & 255;
		state[a] = (byte)(times (14, s_a) ^ times (11, s_b) ^
			times (13, s_c) ^ times (9, s_d));
		state[b] = (byte)(times (9, s_a) ^ times (14, s_b) ^
			times (11, s_c) ^ times (13, s_d));
		state[c] = (byte)(times (13, s_a) ^ times (9, s_b) ^
			times (14, s_c) ^ times (11, s_d));
		state[d] = (byte)(times (11, s_a) ^ times (13, s_b) ^
			times (9, s_c) ^ times (14, s_d));
		}

	/**
	 * The AES S-box.
	 */
	private static final byte[] sbox = new byte[]
		{
		/* 0x00 */ (byte) 0x63,
		/* 0x01 */ (byte) 0x7c,
		/* 0x02 */ (byte) 0x77,
		/* 0x03 */ (byte) 0x7b,
		/* 0x04 */ (byte) 0xf2,
		/* 0x05 */ (byte) 0x6b,
		/* 0x06 */ (byte) 0x6f,
		/* 0x07 */ (byte) 0xc5,
		/* 0x08 */ (byte) 0x30,
		/* 0x09 */ (byte) 0x01,
		/* 0x0A */ (byte) 0x67,
		/* 0x0B */ (byte) 0x2b,
		/* 0x0C */ (byte) 0xfe,
		/* 0x0D */ (byte) 0xd7,
		/* 0x0E */ (byte) 0xab,
		/* 0x0F */ (byte) 0x76,
		/* 0x10 */ (byte) 0xca,
		/* 0x11 */ (byte) 0x82,
		/* 0x12 */ (byte) 0xc9,
		/* 0x13 */ (byte) 0x7d,
		/* 0x14 */ (byte) 0xfa,
		/* 0x15 */ (byte) 0x59,
		/* 0x16 */ (byte) 0x47,
		/* 0x17 */ (byte) 0xf0,
		/* 0x18 */ (byte) 0xad,
		/* 0x19 */ (byte) 0xd4,
		/* 0x1A */ (byte) 0xa2,
		/* 0x1B */ (byte) 0xaf,
		/* 0x1C */ (byte) 0x9c,
		/* 0x1D */ (byte) 0xa4,
		/* 0x1E */ (byte) 0x72,
		/* 0x1F */ (byte) 0xc0,
		/* 0x20 */ (byte) 0xb7,
		/* 0x21 */ (byte) 0xfd,
		/* 0x22 */ (byte) 0x93,
		/* 0x23 */ (byte) 0x26,
		/* 0x24 */ (byte) 0x36,
		/* 0x25 */ (byte) 0x3f,
		/* 0x26 */ (byte) 0xf7,
		/* 0x27 */ (byte) 0xcc,
		/* 0x28 */ (byte) 0x34,
		/* 0x29 */ (byte) 0xa5,
		/* 0x2A */ (byte) 0xe5,
		/* 0x2B */ (byte) 0xf1,
		/* 0x2C */ (byte) 0x71,
		/* 0x2D */ (byte) 0xd8,
		/* 0x2E */ (byte) 0x31,
		/* 0x2F */ (byte) 0x15,
		/* 0x30 */ (byte) 0x04,
		/* 0x31 */ (byte) 0xc7,
		/* 0x32 */ (byte) 0x23,
		/* 0x33 */ (byte) 0xc3,
		/* 0x34 */ (byte) 0x18,
		/* 0x35 */ (byte) 0x96,
		/* 0x36 */ (byte) 0x05,
		/* 0x37 */ (byte) 0x9a,
		/* 0x38 */ (byte) 0x07,
		/* 0x39 */ (byte) 0x12,
		/* 0x3A */ (byte) 0x80,
		/* 0x3B */ (byte) 0xe2,
		/* 0x3C */ (byte) 0xeb,
		/* 0x3D */ (byte) 0x27,
		/* 0x3E */ (byte) 0xb2,
		/* 0x3F */ (byte) 0x75,
		/* 0x40 */ (byte) 0x09,
		/* 0x41 */ (byte) 0x83,
		/* 0x42 */ (byte) 0x2c,
		/* 0x43 */ (byte) 0x1a,
		/* 0x44 */ (byte) 0x1b,
		/* 0x45 */ (byte) 0x6e,
		/* 0x46 */ (byte) 0x5a,
		/* 0x47 */ (byte) 0xa0,
		/* 0x48 */ (byte) 0x52,
		/* 0x49 */ (byte) 0x3b,
		/* 0x4A */ (byte) 0xd6,
		/* 0x4B */ (byte) 0xb3,
		/* 0x4C */ (byte) 0x29,
		/* 0x4D */ (byte) 0xe3,
		/* 0x4E */ (byte) 0x2f,
		/* 0x4F */ (byte) 0x84,
		/* 0x50 */ (byte) 0x53,
		/* 0x51 */ (byte) 0xd1,
		/* 0x52 */ (byte) 0x00,
		/* 0x53 */ (byte) 0xed,
		/* 0x54 */ (byte) 0x20,
		/* 0x55 */ (byte) 0xfc,
		/* 0x56 */ (byte) 0xb1,
		/* 0x57 */ (byte) 0x5b,
		/* 0x58 */ (byte) 0x6a,
		/* 0x59 */ (byte) 0xcb,
		/* 0x5A */ (byte) 0xbe,
		/* 0x5B */ (byte) 0x39,
		/* 0x5C */ (byte) 0x4a,
		/* 0x5D */ (byte) 0x4c,
		/* 0x5E */ (byte) 0x58,
		/* 0x5F */ (byte) 0xcf,
		/* 0x60 */ (byte) 0xd0,
		/* 0x61 */ (byte) 0xef,
		/* 0x62 */ (byte) 0xaa,
		/* 0x63 */ (byte) 0xfb,
		/* 0x64 */ (byte) 0x43,
		/* 0x65 */ (byte) 0x4d,
		/* 0x66 */ (byte) 0x33,
		/* 0x67 */ (byte) 0x85,
		/* 0x68 */ (byte) 0x45,
		/* 0x69 */ (byte) 0xf9,
		/* 0x6A */ (byte) 0x02,
		/* 0x6B */ (byte) 0x7f,
		/* 0x6C */ (byte) 0x50,
		/* 0x6D */ (byte) 0x3c,
		/* 0x6E */ (byte) 0x9f,
		/* 0x6F */ (byte) 0xa8,
		/* 0x70 */ (byte) 0x51,
		/* 0x71 */ (byte) 0xa3,
		/* 0x72 */ (byte) 0x40,
		/* 0x73 */ (byte) 0x8f,
		/* 0x74 */ (byte) 0x92,
		/* 0x75 */ (byte) 0x9d,
		/* 0x76 */ (byte) 0x38,
		/* 0x77 */ (byte) 0xf5,
		/* 0x78 */ (byte) 0xbc,
		/* 0x79 */ (byte) 0xb6,
		/* 0x7A */ (byte) 0xda,
		/* 0x7B */ (byte) 0x21,
		/* 0x7C */ (byte) 0x10,
		/* 0x7D */ (byte) 0xff,
		/* 0x7E */ (byte) 0xf3,
		/* 0x7F */ (byte) 0xd2,
		/* 0x80 */ (byte) 0xcd,
		/* 0x81 */ (byte) 0x0c,
		/* 0x82 */ (byte) 0x13,
		/* 0x83 */ (byte) 0xec,
		/* 0x84 */ (byte) 0x5f,
		/* 0x85 */ (byte) 0x97,
		/* 0x86 */ (byte) 0x44,
		/* 0x87 */ (byte) 0x17,
		/* 0x88 */ (byte) 0xc4,
		/* 0x89 */ (byte) 0xa7,
		/* 0x8A */ (byte) 0x7e,
		/* 0x8B */ (byte) 0x3d,
		/* 0x8C */ (byte) 0x64,
		/* 0x8D */ (byte) 0x5d,
		/* 0x8E */ (byte) 0x19,
		/* 0x8F */ (byte) 0x73,
		/* 0x90 */ (byte) 0x60,
		/* 0x91 */ (byte) 0x81,
		/* 0x92 */ (byte) 0x4f,
		/* 0x93 */ (byte) 0xdc,
		/* 0x94 */ (byte) 0x22,
		/* 0x95 */ (byte) 0x2a,
		/* 0x96 */ (byte) 0x90,
		/* 0x97 */ (byte) 0x88,
		/* 0x98 */ (byte) 0x46,
		/* 0x99 */ (byte) 0xee,
		/* 0x9A */ (byte) 0xb8,
		/* 0x9B */ (byte) 0x14,
		/* 0x9C */ (byte) 0xde,
		/* 0x9D */ (byte) 0x5e,
		/* 0x9E */ (byte) 0x0b,
		/* 0x9F */ (byte) 0xdb,
		/* 0xA0 */ (byte) 0xe0,
		/* 0xA1 */ (byte) 0x32,
		/* 0xA2 */ (byte) 0x3a,
		/* 0xA3 */ (byte) 0x0a,
		/* 0xA4 */ (byte) 0x49,
		/* 0xA5 */ (byte) 0x06,
		/* 0xA6 */ (byte) 0x24,
		/* 0xA7 */ (byte) 0x5c,
		/* 0xA8 */ (byte) 0xc2,
		/* 0xA9 */ (byte) 0xd3,
		/* 0xAA */ (byte) 0xac,
		/* 0xAB */ (byte) 0x62,
		/* 0xAC */ (byte) 0x91,
		/* 0xAD */ (byte) 0x95,
		/* 0xAE */ (byte) 0xe4,
		/* 0xAF */ (byte) 0x79,
		/* 0xB0 */ (byte) 0xe7,
		/* 0xB1 */ (byte) 0xc8,
		/* 0xB2 */ (byte) 0x37,
		/* 0xB3 */ (byte) 0x6d,
		/* 0xB4 */ (byte) 0x8d,
		/* 0xB5 */ (byte) 0xd5,
		/* 0xB6 */ (byte) 0x4e,
		/* 0xB7 */ (byte) 0xa9,
		/* 0xB8 */ (byte) 0x6c,
		/* 0xB9 */ (byte) 0x56,
		/* 0xBA */ (byte) 0xf4,
		/* 0xBB */ (byte) 0xea,
		/* 0xBC */ (byte) 0x65,
		/* 0xBD */ (byte) 0x7a,
		/* 0xBE */ (byte) 0xae,
		/* 0xBF */ (byte) 0x08,
		/* 0xC0 */ (byte) 0xba,
		/* 0xC1 */ (byte) 0x78,
		/* 0xC2 */ (byte) 0x25,
		/* 0xC3 */ (byte) 0x2e,
		/* 0xC4 */ (byte) 0x1c,
		/* 0xC5 */ (byte) 0xa6,
		/* 0xC6 */ (byte) 0xb4,
		/* 0xC7 */ (byte) 0xc6,
		/* 0xC8 */ (byte) 0xe8,
		/* 0xC9 */ (byte) 0xdd,
		/* 0xCA */ (byte) 0x74,
		/* 0xCB */ (byte) 0x1f,
		/* 0xCC */ (byte) 0x4b,
		/* 0xCD */ (byte) 0xbd,
		/* 0xCE */ (byte) 0x8b,
		/* 0xCF */ (byte) 0x8a,
		/* 0xD0 */ (byte) 0x70,
		/* 0xD1 */ (byte) 0x3e,
		/* 0xD2 */ (byte) 0xb5,
		/* 0xD3 */ (byte) 0x66,
		/* 0xD4 */ (byte) 0x48,
		/* 0xD5 */ (byte) 0x03,
		/* 0xD6 */ (byte) 0xf6,
		/* 0xD7 */ (byte) 0x0e,
		/* 0xD8 */ (byte) 0x61,
		/* 0xD9 */ (byte) 0x35,
		/* 0xDA */ (byte) 0x57,
		/* 0xDB */ (byte) 0xb9,
		/* 0xDC */ (byte) 0x86,
		/* 0xDD */ (byte) 0xc1,
		/* 0xDE */ (byte) 0x1d,
		/* 0xDF */ (byte) 0x9e,
		/* 0xE0 */ (byte) 0xe1,
		/* 0xE1 */ (byte) 0xf8,
		/* 0xE2 */ (byte) 0x98,
		/* 0xE3 */ (byte) 0x11,
		/* 0xE4 */ (byte) 0x69,
		/* 0xE5 */ (byte) 0xd9,
		/* 0xE6 */ (byte) 0x8e,
		/* 0xE7 */ (byte) 0x94,
		/* 0xE8 */ (byte) 0x9b,
		/* 0xE9 */ (byte) 0x1e,
		/* 0xEA */ (byte) 0x87,
		/* 0xEB */ (byte) 0xe9,
		/* 0xEC */ (byte) 0xce,
		/* 0xED */ (byte) 0x55,
		/* 0xEE */ (byte) 0x28,
		/* 0xEF */ (byte) 0xdf,
		/* 0xF0 */ (byte) 0x8c,
		/* 0xF1 */ (byte) 0xa1,
		/* 0xF2 */ (byte) 0x89,
		/* 0xF3 */ (byte) 0x0d,
		/* 0xF4 */ (byte) 0xbf,
		/* 0xF5 */ (byte) 0xe6,
		/* 0xF6 */ (byte) 0x42,
		/* 0xF7 */ (byte) 0x68,
		/* 0xF8 */ (byte) 0x41,
		/* 0xF9 */ (byte) 0x99,
		/* 0xFA */ (byte) 0x2d,
		/* 0xFB */ (byte) 0x0f,
		/* 0xFC */ (byte) 0xb0,
		/* 0xFD */ (byte) 0x54,
		/* 0xFE */ (byte) 0xbb,
		/* 0xFF */ (byte) 0x16,
		};

	/**
	 * The AES inverse S-box.
	 */
	private static final byte[] invSbox = new byte [256];
	static
		{
		for (int i = 0; i <= 255; ++ i)
			invSbox[sbox[i]&255] = (byte) i;
		}

	/**
	 * Unit test main program. Prints test vectors from the AES spec.
	 */
	public static void main
		(String[] args)
		{
		testVector
			(/*key*/ "2b7e151628aed2a6abf7158809cf4f3c",
			 /*pt */ "3243f6a8885a308d313198a2e0370734",
			 /*ct */ "3925841d02dc09fbdc118597196a0b32");
		testVector
			(/*key*/ "000102030405060708090a0b0c0d0e0f",
			 /*pt */ "00112233445566778899aabbccddeeff",
			 /*ct */ "69c4e0d86a7b0430d8cdb78070b4c55a");
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
		AES128 cipher = new AES128();
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
