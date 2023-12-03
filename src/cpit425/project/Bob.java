
package cpit425.project;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author manar
 */
public class Bob {

    private byte[] dcrypted;
    private final Cipher cipher;
    private String decryprtedText;
    private final PrivateKey privateKey_Bob;
    private final PublicKey publicKey_Bob;
    private final Cipher c;
    private byte[] decryptedKey;

    public Bob() throws NoSuchAlgorithmException, NoSuchPaddingException {

        // create the Cipher object with AES algorithm
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        c = Cipher.getInstance("RSA");

        // generate the Key pair for RSA algorithm 
        KeyPairGenerator keybob = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPairbob = keybob.genKeyPair();
        privateKey_Bob = keyPairbob.getPrivate();
        publicKey_Bob = keyPairbob.getPublic();

    }

    public String DecryprtionMessage(Alice a, byte[] key,String Ecrypted) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        // generate secret key using AES
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        // decrypt initialize the same cipher object, set mode to decrypt and pass the key and iv
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, a.getIv());
        // decrypt using doFinal and use Base64 due to input length must be multiple of 16 when decrypting with padded cipher
        dcrypted = cipher.doFinal(Base64.getDecoder().decode(Ecrypted.getBytes()));
        // convert byte array to string for printing 
        decryprtedText = new String(dcrypted);
        return decryprtedText;
    }

    public byte[] DecryprtionKey(String key) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        // decrypt initialize the same cipher object, set mode to decrypt and pass the private key 
        c.init(Cipher.DECRYPT_MODE, privateKey_Bob);
        // decrypt using doFinal
        decryptedKey = c.doFinal(Base64.getDecoder().decode(key.getBytes()));
        return decryptedKey;
    }

    public byte[] getDcrypted() {
        return dcrypted;
    }

    public String getOutput2() {
        return decryprtedText;
    }

    public PrivateKey getPrivatekey_bob() {
        return privateKey_Bob;
    }

    public PublicKey getPublickey_bob() {
        return publicKey_Bob;
    }

}
