package net.mewk.pem;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;

public class PEMUtils {

    /**
     * Loads a private key in the PEM format.
     *
     * @param fileName The filename of the private key
     * @return The key pair containing the private and public key
     * @throws IOException
     */
    public static KeyPair loadPrivateKey(String fileName) throws IOException {
        Reader bufferedReader = null;
        PEMParser pemParser = null;

        try {
            bufferedReader = new BufferedReader(new InputStreamReader(PEMUtils.class.getResourceAsStream(fileName)));
            pemParser = new PEMParser(bufferedReader);
            PEMKeyPair pemPair = (PEMKeyPair) pemParser.readObject();

            return new JcaPEMKeyConverter().setProvider("BC").getKeyPair(pemPair);
        } finally {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (pemParser != null) {
                pemParser.close();
            }
        }
    }

    /**
     * Loads a public key in the PEM format.
     *
     * @param fileName The filename of the public key
     * @return The public key
     * @throws IOException
     */
    public static PublicKey loadPublicKey(String fileName) throws IOException {
        Reader bufferedReader = null;
        PEMParser pemParser = null;

        try {
            bufferedReader = new BufferedReader(new InputStreamReader(PEMUtils.class.getResourceAsStream(fileName)));
            pemParser = new PEMParser(bufferedReader);
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();

            return new JcaPEMKeyConverter().setProvider("BC").getPublicKey(subjectPublicKeyInfo);
        } finally {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
            if (pemParser != null) {
                pemParser.close();
            }
        }
    }

    /**
     * Encrypts a message.
     *
     * @param text The message to be encrypted
     * @param key The public key
     * @param algorithm The encryption algorithm
     * @return The encrypted message
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static byte[] encrypt(String text, PublicKey key, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(text.getBytes());
    }

    /**
     * Decrypts a message.
     *
     * @param text The message to be decrypted
     * @param key The private key
     * @param algorithm The encryption algorithm
     * @return The decrypted message
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     */
    public static String decrypt(byte[] text, PrivateKey key, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        final Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);

        return new String(cipher.doFinal(text));
    }
}