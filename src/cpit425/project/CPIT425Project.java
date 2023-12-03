
package cpit425.project;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.JOptionPane;

/**
 *
 * @author manar
 */
public class CPIT425Project {

    /**
     * @param args the command line arguments
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
     public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    
        // create alice and bob objects 
        Alice alice = new Alice();
        Bob bob = new Bob();
        // string that we want to encrypt
        String plaintext = JOptionPane.showInputDialog("- - - - - - - - - - - - - -WELCOME- - - - - - - - - - - - - - - - \n Input your message that will be sent to Bob: \n\n"); 
        // to input the plaintext
        String ciphertext;

        if (plaintext == null) {
            JOptionPane.showMessageDialog(null, "The message was not sent to Bob " + "\n",
                     " Output", JOptionPane.INFORMATION_MESSAGE);
            System.out.println("The message was not sent to Bob");
            System.exit(0);
         } else {
            plaintext = alice.EncryptionMessage(plaintext);
        }
        
        ciphertext = bob.DecryprtionMessage(alice, bob.DecryprtionKey(alice.EncryptionKey(bob)),plaintext);
        // get the encrypted text and decrypted text
        JOptionPane.showMessageDialog(null, "\nEncrypted Message: " + plaintext + "\n"
                + "Decrypted Message: " + ciphertext
                + "\n\n", " Output", JOptionPane.INFORMATION_MESSAGE);

        System.out.println("-----------------------WELCOME------------------------\n");
        // get the encrypted text
        System.out.println("Encrypted Message: " + plaintext);
        // get the decrypted text
        System.out.println("Decrypted Message: " + ciphertext + "\n");
    }
}
