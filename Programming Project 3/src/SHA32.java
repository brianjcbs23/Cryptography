import edu.rit.util.Packing;

/**
 * Class SHA32 implements the SHA-256 hash function, returning the most significant 32 bits.
 *
 * @author  Alan Kaminsky
 * @author  Brian Jacobs
 * @version 05-Apr-2017
 */
public class SHA32
	implements HashFunction
	{

	private byte[] messageBlock = new byte [64];
	private long byteCount;
	private int[] H = new int [8];
	private int[] W = new int [64];

	/**
	 * Construct a new SHA-32 hash function object.
	 */
	public SHA32()
		{
		reset();
		}

	/**
	 * Returns this hash function's digest size in bytes.
	 *
	 * @return  Digest size.
	 */
	public int digestSize()
		{
		return 4;
		}

	/**
	 * Append the given byte to the message being hashed. Only the least
	 * significant 8 bits of <TT>b</TT> are used.
	 *
	 * @param  b  Message byte.
	 */
	public void append
		(int b)
		{
		accumulate ((byte)b);
		}

	/**
	 * Append the given byte array to the message being hashed.
	 *
	 * @param  buf  Message byte array.
	 */
	public void append
		(byte[] buf)
		{
		append (buf, 0, buf.length);
		}

	/**
	 * Append a portion of the given byte array to the message being hashed.
	 *
	 * @param  buf  Message byte array.
	 * @param  off  Index of first byte from <TT>buf</TT> to append.
	 * @param  len  Number of bytes from <TT>buf</TT> to append.
	 *
	 * @exception  IndexOutOfBoundsException
	 *     (unchecked exception) Thrown if <TT>off</TT> &lt; 0, <TT>len</TT>
	 *     &lt; 0, or <TT>off+len</TT> &gt; <TT>buf.length</TT>.
	 */
	public void append
		(byte[] buf,
		 int off,
		 int len)
		{
		if (off < 0 || len < 0 || off + len > buf.length)
			throw new IndexOutOfBoundsException (String.format
				("SHA32.append(): off = %d, len = %d out of bounds",
				 off, len));
		for (int i = 0; i < len; ++ i)
			accumulate (buf[off+i]);
		}

	/**
	 * Accumulate the given byte into the hash computation.
	 *
	 * @param  b  Byte.
	 */
	private void accumulate
		(byte b)
		{
		messageBlock[(int)(byteCount & 63)] = b;
		++ byteCount;
		if ((byteCount & 63) == 0)
			compress();
		}

	/**
	 * Obtain the message digest. <TT>d</TT> must be an array of bytes whose
	 * length is equal to <TT>digestSize()</TT>. The message consists of the
	 * series of bytes provided to the <TT>append()</TT> methods. The digest of
	 * the message is stored in the <TT>d</TT> array. This hash function object
	 * is reset, so that further calls to the <TT>append()</TT> methods will
	 * compute a new digest.
	 *
	 * @param  d  Message digest (output).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>d.length</TT> &ne;
	 *     <TT>digestSize()</TT>.
	 */
	public void digest
		(byte[] d)
		{
		// Verify preconditions.
		if (d.length != 4)
			throw new IllegalArgumentException("SHA32.digest(): d must be 4 bytes");

		// Pad the message.
		long bitlen = 8*byteCount;
		accumulate ((byte)0x80);
		while ((byteCount & 63) != 56)
			accumulate ((byte)0);
		Packing.unpackLongBigEndian (bitlen, messageBlock, 56);

		// One final compression.
		compress();

		// Output digest and reset.
		byte[] tmp = new byte[32];
		Packing.unpackIntBigEndian (H, 0, tmp, 0, 8);
		for (int i = 0; i < d.length; ++i){
			d[i] = tmp[i];
		}
		reset();
		}

	/**
	 * Reset this hash function. Further calls to the <TT>append()</TT> methods
	 * will compute a new digest.
	 */
	public void reset()
		{
		byteCount = 0;
		H[0] = 0xdd33bf70;
		H[1] = 0x4e7df5f2;
		H[2] = 0x7c8b28a7;
		H[3] = 0x69b05818;
		H[4] = 0xa62b7478;
		H[5] = 0x9497194a;
		H[6] = 0x82895dad;
		H[7] = 0x127abaf9;
		}

	// SHA-32 little functions.
	private static int Ch (int x, int y, int z)
		{
		return (x & y) ^ (~x & z);
		}
	private static int Maj (int x, int y, int z)
		{
		return (x & y) ^ (x & z) ^ (y & z);
		}
	private static int Sigma_0 (int x)
		{
		return Integer.rotateRight (x, 2) ^
			Integer.rotateRight (x, 13) ^
			Integer.rotateRight (x, 22);
		}
	private static int Sigma_1 (int x)
		{
		return Integer.rotateRight (x, 6) ^
			Integer.rotateRight (x, 11) ^
			Integer.rotateRight (x, 25);
		}
	private static int sigma_0 (int x)
		{
		return Integer.rotateRight (x, 7) ^
			Integer.rotateRight (x, 18) ^
			(x >>> 3);
		}
	private static int sigma_1 (int x)
		{
		return Integer.rotateRight (x, 17) ^
			Integer.rotateRight (x, 19) ^
			(x >>> 10);
		}

	// SHA-32 constants.
	private static int[] K = new int[]
		{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
		0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
		0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
		0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
		0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
		0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
		0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, 
		};

	// SHA-32 compression function.
	private void compress()
		{
		// Prepare the message schedule W.
		Packing.packIntBigEndian (messageBlock, 0, W, 0, 16);
		for (int t = 16; t <= 63; ++ t)
			W[t] = sigma_1(W[t-2]) + W[t-7] + sigma_0(W[t-15]) + W[t-16];

		// Initialize working variables.
		int a = H[0];
		int b = H[1];
		int c = H[2];
		int d = H[3];
		int e = H[4];
		int f = H[5];
		int g = H[6];
		int h = H[7];

		// Do 64 rounds.
		int T_1, T_2;
		for (int t = 0; t <= 63; ++ t)
			{
			T_1 = h + Sigma_1(e) + Ch(e,f,g) + K[t] + W[t];
			T_2 = Sigma_0(a) + Maj(a,b,c);
			h = g;
			g = f;
			f = e;
			e = d + T_1;
			d = c;
			c = b;
			b = a;
			a = T_1 + T_2;
			}

		// Output chaining value.
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
		}

	}
