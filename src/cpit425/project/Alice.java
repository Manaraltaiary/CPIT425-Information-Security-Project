
package cpit425.project;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 *
 * @author manar
 */
public class Alice {
    
   private final Cipher cipher;
    private final byte[] AES_Key;
    private final SecretKey secretKey;
    private String encryptedText;
    private final IvParameterSpec iv;
    private final Cipher c;
    private final PrivateKey privateKey_Alice;
    private final PublicKey publicKey_Alice;
    private String encryptedKey;

    public Alice() throws NoSuchAlgorithmException, NoSuchPaddingException {

        // generate the Key for AES algorithm to use it in encrypion and decryption meassage
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        // generate the secret key 
        secretKey = keyGenerator.generateKey();
        // converting the secretKey to array of byte to encrypt it and send it to bob encrypted
        AES_Key = secretKey.getEncoded();
        // create the Cipher object with AES algorithm
        cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

        // generate the Key pair for RSA algorithm to use it in encrypion and decryption Key
        KeyPairGenerator keyAlice = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPairAlice = keyAlice.genKeyPair();
        privateKey_Alice = keyPairAlice.getPrivate();
        publicKey_Alice = keyPairAlice.getPublic();

        // create the Cipher object with RSA algorithm
        c = Cipher.getInstance("RSA");

        // iv initiation 
        new SecureRandom().nextBytes(new byte[16]);
        iv = new IvParameterSpec(new byte[16]);
    }

    public String EncryptionMessage(String Message) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // initialize the cipherobject, set mode to encrypt and pass the key with iv
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        // encrypt the message using doFinal
        byte[] encryptedBytes = cipher.doFinal(Message.getBytes());
        // convert the byte array to a readable string use the encoding scheme "base64" 
        encryptedText = new String(Base64.getEncoder().encode(encryptedBytes));
        return encryptedText;
    }
    public String EncryptionKey(Bob b) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        // initialize the cipherobject, set mode to encrypt and pass the public key of bob so he can decryption the key by using his private key
        c.init(Cipher.ENCRYPT_MODE, b.getPublickey_bob());
        // encrypt the message using doFinal
        byte[] encryptedBytes = c.doFinal(AES_Key);
        // convert the byte array to a readable string use the encoding scheme "base64" 
        encryptedKey = Base64.getEncoder().encodeToString(encryptedBytes);
        return encryptedKey;
    }

    public String getEncryptedText() {
        return encryptedText;
    }

    public IvParameterSpec getIv() {
        return iv;
    }

    public PrivateKey getPrivatekey_Alice() {
        return privateKey_Alice;
    }

    public PublicKey getPublickey_Alice() {
        return publicKey_Alice;
    }

}
