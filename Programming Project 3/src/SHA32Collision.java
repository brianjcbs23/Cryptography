import edu.rit.util.Hex;
import java.util.Arrays;
import java.util.Map;
import java.util.HashMap;

/**
 * Class SHA32Collision is a unit test main program for the SHA32 class
 * that finds collisions in the SHA32 algorithm
 *
 * <P>
 * Usage: <TT>java SHA32Collision <I>initialHexValue</I>
 * <I>preimage</I>
 * <I>preimage</I>
 * <I>commonDigest</I></TT>
 *
 * @author Brian Jacobs
 * @version 05-Apr-2017
 */
public class SHA32Collision
    {
        /**
         * Main program
         */
        public static void main(String[] args){
            // Parse command line arguments
            if (args.length != 1) usage();
            SHA32 hasher = new SHA32();
            byte[] message = Hex.toByteArray (args[0]);

            // Compute the first digest
            byte[] d = new byte [hasher.digestSize()];
            hasher.append (message);
            hasher.digest (d);

            byte[] c = new byte [hasher.digestSize()];
            int tmpInt = Hex.toInt(args[0]);
            Map<String, String> m = new HashMap<String, String>();

            while (true){
                // Increment to the hex message by 1
                ++tmpInt;
                String tmpString = Hex.toString(tmpInt);
                c = Hex.toByteArray(tmpString);

                // Calculate the new digest
                hasher.append (c);
                hasher.digest(c);
                String digest = Hex.toString(c);

                // Check to see if the computed digest has already been calculated
                if(m.containsKey(digest)){
                    System.out.printf(tmpString);
                    System.out.printf(" ");
                    System.out.println();
                    System.out.printf(m.get(digest));
                    System.out.println();
                    System.out.printf(digest);
                    System.out.println();
                    break;
                }
                m.put(digest, tmpString);
            }
        }

        /**
        * Print a usage message and exit.
        */
        private static void usage(){
            System.err.println ("Usage: java SHA32Collision <initialization>");
            System.err.println ("<initialization> = Initialization Vector (hexadecimal)");
            System.exit (1);
        }
    }
