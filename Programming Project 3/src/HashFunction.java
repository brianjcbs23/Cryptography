/**
 * Interface HashFunction specifies the interface for a hash function object.
 *
 * @author  Alan Kaminsky
 * @version 06-Apr-2016
 */
public interface HashFunction
	{

	/**
	 * Returns this hash function's digest size in bytes.
	 *
	 * @return  Digest size.
	 */
	public int digestSize();

	/**
	 * Append the given byte to the message being hashed. Only the least
	 * significant 8 bits of <TT>b</TT> are used.
	 *
	 * @param  b  Message byte.
	 */
	public void append
		(int b);

	/**
	 * Append the given byte array to the message being hashed.
	 *
	 * @param  buf  Message byte array.
	 */
	public void append
		(byte[] buf);

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
		 int len);

	/**
	 * Obtain the message digest. <TT>d</TT> must be an array of bytes whose
	 * length is equal to <TT>digestSize()</TT>. The message consists of the
	 * series of bytes provided to the <TT>hash()</TT> methods. The digest of
	 * the message is stored in the <TT>d</TT> array. This hash function object
	 * is reset, so that further calls to the <TT>hash()</TT> methods will
	 * compute a new digest.
	 *
	 * @param  d  Message digest (output).
	 *
	 * @exception  IllegalArgumentException
	 *     (unchecked exception) Thrown if <TT>d.length</TT> &ne;
	 *     <TT>digestSize()</TT>.
	 */
	public void digest
		(byte[] d);

	/**
	 * Reset this hash function. Further calls to the <TT>hash()</TT> methods
	 * will compute a new digest.
	 */
	public void reset();

	}
