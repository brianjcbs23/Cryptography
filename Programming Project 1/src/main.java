/**
 * Created by brianjacobs on 2/11/17.
 */
public class main {
    public static void main(String args[]) throws Exception {
        RC4A encryptCipher = new RC4A();
        byte[] key = new byte[32];
        for(byte i = 0; i <= 31; ++i) key[i] = i;
        encryptCipher.setKey(key);

        byte[] Skey = encryptCipher.getSkey();
        byte[] Snoce = encryptCipher.getSnonce();
        for(int i = 0; i < Skey.length; ++i) System.out.printf("%02x ", Skey[i]);
        System.out.println();
        for(int i = 0; i < Snoce.length; ++i) System.out.printf("%02x ", Snoce[i]);
        System.out.println();


        byte[] plaintext = new byte[] {0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x20, 0x57, 0x4f, 0x52, 0x4c, 0x44, 0x0a};

//        byte[] plaintext = new byte[128];
//        for(int i = 0; i < 128; ++i)plaintext[i] = 0;

        for(int i = 0; i < plaintext.length; ++i) System.out.printf("%02x ", plaintext[i]);
        System.out.println();

        int[] ciphertext = new int[plaintext.length];
        for(int i = 0; i < ciphertext.length; ++i){
            ciphertext[i] = encryptCipher.encrypt(plaintext[i]);
            System.out.printf("%02x ", ciphertext[i]);
        }

        System.out.println();

        RC4A decryptCipher = new RC4A();
        decryptCipher.setKey(key);
        int[] decryptedtext = new int[ciphertext.length];
        for(int i = 0; i < decryptedtext.length; ++i){
            decryptedtext[i] = decryptCipher.decrypt(ciphertext[i]);
            System.out.printf("%02x ", decryptedtext[i]);
        }
    }
}
