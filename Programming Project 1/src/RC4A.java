/**
 * Class RC4A implements the RC4A stream cipher.
 *
 * @author  Brian Jacobs
 * @version 09-Feb-2017
 */
public class RC4A implements StreamCipher{

    private byte[] Skey = new byte[256];
    private byte[] Snonce = new byte[256];
    private boolean switchVar;
    private int x;
    private int y;
    private int z;


    /**
     * Returns this stream cipher's key size in bytes. If the stream cipher
     * includes both a key and a nonce, <TT>keySize()</TT> returns the size of
     * the key plus the size of the nonce in bytes.
     * <P>
     * For class RC4A, the key size is fixed at 16 bytes with a NONCE of 16 bytes as well.
     *
     * @return  Key + NONCE size.
     */
    public int keySize(){
        return 32;
    }

    /**
     * Set the key for this stream cipher. <TT>key</TT> must be an array of
     * bytes whose length is equal to <TT>keySize()</TT>. If the stream cipher
     * includes both a key and a nonce, <TT>key</TT> contains the bytes of the
     * key followed by the bytes of the nonce. The keystream generator is
     * initialized, such that successive calls to <TT>encrypt()</TT> or
     * <TT>decrypt()</TT> will encrypt or decrypt a series of bytes.
     * <P>
     * For class RC4A, bytes <TT>key[0]</TT> through <TT>key[15]</TT> are used as the key
     * and bytes <TT>key[16]</TT> through <TT>key[31]</TT>.
     *
     * @param  key  Key.
     *
     * @exception  IllegalArgumentException
     *     (unchecked exception) Thrown if <TT>key.length</TT> &ne;
     *     <TT>keySize()</TT>.
     */
    public void setKey (byte[] key){
        if (key.length != 32){
            throw new IllegalArgumentException("RC4A.setKey(): key must be 16 bytes and NONCE must be 16 bytes");
        }

        for(int i = 0; i <= 255; ++i){
            Skey[i] = (byte)i;
            Snonce[i] = (byte)i;
        }

        int j = 0;
        int k = 0;

        for(int i = 0; i <= 255; ++i){
            j = (j + Skey[i] + key[i & 15]) & 255;
            k = (k + Snonce[i] + key[(i & 15) + 16]) & 255;
            swap(i, j, k);
        }

        x = 0;
        y = 0;
        z = 0;
        switchVar = true;


    }

    /**
     * Encrypt the given byte. Only the least significant 8 bits of <TT>b</TT>
     * are used. The ciphertext byte is returned as a value from 0 to 255.
     *
     * @param  b  Plaintext byte.
     *
     * @return  Ciphertext byte.
     */
    public int encrypt (int b){
        return encryptOrDecrypt(b);
    }

    /**
     * Decrypt the given byte. Only the least significant 8 bits of <TT>b</TT>
     * are used. The plaintext byte is returned as a value from 0 to 255.
     *
     * @param  b  Ciphertext byte.
     *
     * @return  Plaintext byte.
     */
    public int decrypt (int b){
        return encryptOrDecrypt(b);
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
    private int encryptOrDecrypt(int b){
        if(switchVar) {
            x = (x + 1) & 255;
            y = (y + Skey[x]) & 255;
            swap(x, y, Skey);
            switchVar = false;
            return (Skey[(Skey[x] + Skey[y]) & 255] ^ b) & 255;
        }
        else {
            z = (z + Snonce[x]) & 15;
            swap(x, z, Snonce);
            switchVar = true;
            return (Snonce[(Snonce[x] + Snonce[z]) & 255] ^ b) & 255;
        }
    }

    /**
     * Swap Skey[i] with Skey[j] and swap Snoce[i] with Snoce[k]
     */
    private void swap (int i, int j, int k){
        byte t = Skey[i];
        Skey[i] = Skey[j];
        Skey[j] = t;

        t = Snonce[i];
        Snonce[i] = Snonce[k];
        Snonce[k] = t;
    }

    /**
     * Swap S[i] with S[j]
     */
    private void swap(int i, int j, byte[] S){
        byte t = S[i];
        S[i] = S[j];
        S[j] = t;
    }
    
}