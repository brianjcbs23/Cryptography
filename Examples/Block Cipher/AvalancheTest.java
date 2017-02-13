import edu.rit.numeric.Histogram;
import edu.rit.numeric.Mathe;
import edu.rit.util.Hex;
import edu.rit.util.Instance;

/**
 * Class AvalancheTest performs a statistical test on a block cipher. The
 * program examines a series of plaintexts, each of which differs from its
 * predecessor in one bit position. The program computes the corresponding
 * ciphertexts, measures the Hamming distance between each ciphertext and its
 * predecessor, and observes the probability distribution of the Hamming
 * distances. For an ideal block cipher that exhibits the avalanche effect, the
 * Hamming distances should obey a binomial(N,0.5) distribution, where N is the
 * block size in bits. The program applies a chi-square test to the observed
 * Hamming distance distribution. The program performs the test for the block
 * cipher reduced to 1 round, 2 rounds, and so on up to the full number of
 * rounds.
 * <P>
 * Usage: <TT>java AvalancheTest <I>cipherClass</I> <I>key</I> <I>plaintext</I>
 * <I>samples</I></TT>
 *
 * @author  Alan Kaminsky
 * @version 17-Feb-2016
 */
public class AvalancheTest
	{
	// Significance threshold.
	private static final double ALPHA = 0.01;

	// Command line arguments.
	private static String cipherClass;
	private static byte[] key;
	private static byte[] text;
	private static int samples;

	// Block size in bytes and bits.
	private static int B;
	private static int N;

	// Arrays of test results.
	private static double[] chisqr;
	private static double[] pvalue;

	/**
	 * Main program.
	 */
	public static void main
		(String[] args)
		throws Exception
		{
		// Parse command line arguments.
		if (args.length != 4) usage();
		cipherClass = args[0];
		key = Hex.toByteArray (args[1]);
		text = Hex.toByteArray (args[2]);
		samples = Integer.parseInt (args[3]);

		// Print provenance.
		System.out.printf ("$ java AvalancheTest");
		for (String arg : args) System.out.printf (" %s", arg);
		System.out.println();

		// Create an instance of the block cipher class.
		BlockCipher cipher = (BlockCipher)
			Instance.newInstance (cipherClass+"()");
		B = cipher.blockSize();
		N = B*8;

		// Verify preconditions.
		if (key.length != cipher.keySize())
			error (String.format ("Key must be %d bytes", cipher.keySize()));
		if (text.length != B)
			error (String.format ("Plaintext must be %d bytes", B));

		// Set up arrays of test results.
		int rounds = cipher.numRounds();
		chisqr = new double [rounds];
		pvalue = new double [rounds];

		// Analyze round-reduced versions.
		for (int R = 1; R <= rounds; ++ R)
			analyze (R);

		// Print test results.
		System.out.printf ("******** SUMMARY ********%n");
		System.out.printf ("round\tchi^2\tpvalue%n");
		for (int R = 1; R <= rounds; ++ R)
			System.out.printf ("%d\t%.4e\t%.4e%s%n",
				R, chisqr[R-1], pvalue[R-1], pvalue[R-1] < ALPHA ? " ***" : "");
		}

	/**
	 * Analyze a block cipher version with the given number of rounds.
	 *
	 * @param  R  Number of rounds.
	 */
	private static void analyze
		(int R)
		throws Exception
		{
		// Create an instance of the block cipher class with R rounds.
		BlockCipher cipher = (BlockCipher)
			Instance.newInstance (cipherClass+"("+R+")");
		cipher.setKey (key);

		// Set up plaintext and ciphertexts.
		byte[] plaintext = (byte[]) text.clone();
		byte[] currentCiphertext = (byte[]) text.clone();
		byte[] previousCiphertext = (byte[]) text.clone();
		cipher.encrypt (previousCiphertext);

		// Set up histogram of Hamming distances. Expected bin probabilities
		// obey a binomial(N,0.5) distribution.
		Histogram hist = new Histogram (N + 1)
			{
			public double expectedProb (int i)
				{
				return Mathe.binomProb (N, i, 0.5);
				}
			};

		// Compute ciphertext samples.
		for (int i = 1; i <= samples; ++ i)
			{
			// Find bit position j of rightmost 1 bit in i.
			int j = 0;
			while ((i & (1 << j)) == 0) ++ j;

			// Flip that bit in the plaintext.
			plaintext[j/8] ^= 1 << (j%8);

			// Compute ciphertext for that plaintext.
			System.arraycopy (plaintext, 0, currentCiphertext, 0, B);
			cipher.encrypt (currentCiphertext);

			// Compute Hamming distance between current and previous
			// ciphertexts, accumulate into histogram.
			hist.accumulate (distance (currentCiphertext, previousCiphertext));

			// Remember previous ciphertext for next sample.
			System.arraycopy (currentCiphertext, 0, previousCiphertext, 0, B);
			}

		// Print histogram.
		System.out.printf ("******** ROUND %d ********%n", R);
		System.out.printf ("dist\tcount\texpect%n");
		for (int i = 0; i <= N; ++ i)
			System.out.printf ("%d\t%d\t%.4e%n",
				i, hist.count(i), hist.expectedCount(i));

		// Print and record test results.
		chisqr[R-1] = hist.chisqr();
		pvalue[R-1] = hist.pvalue (chisqr[R-1]);
		System.out.printf ("chi^2  = %.4e%n", chisqr[R-1]);
		System.out.printf ("pvalue = %.4e%n", pvalue[R-1]);
		}

	/**
	 * Compute the Hamming distance between the given texts.
	 *
	 * @param  a  First text.
	 * @param  b  Second text.
	 *
	 * @return  Hamming distance.
	 */
	private static int distance
		(byte[] a,
		 byte[] b)
		{
		int d = 0;
		for (int i = 0; i < a.length; ++ i)
			d += Integer.bitCount ((a[i] ^ b[i]) & 255);
		return d;
		}

	/**
	 * Print the given error message and exit.
	 *
	 * @param  msg  Error message.
	 */
	private static void error
		(String msg)
		{
		System.err.printf ("AvalancheTest: %s%n", msg);
		usage();
		}

	/**
	 * Print a usage message and exit.
	 */
	private static void usage()
		{
		System.err.println ("Usage: java AvalancheTest <cipherClass> <key> <plaintext> <samples>");
		System.err.println ("<cipherClass> = BlockCipher class name");
		System.err.println ("<key> = Key (hexadecimal)");
		System.err.println ("<plaintext> = Plaintext (hexadecimal)");
		System.err.println ("<samples> = Number of ciphertext samples");
		System.exit (1);
		}

	}
