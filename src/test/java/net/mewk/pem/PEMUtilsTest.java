package net.mewk.pem;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

import static org.junit.Assert.*;

public class PEMUtilsTest {

    private static final String ALGORITHM = "RSA";
    private static final String PRIVATE_KEY = "/private_key.pem";
    private static final String PUBLIC_KEY = "/public_key.pem";

    private File temp;

    @org.junit.Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        temp = File.createTempFile(getClass().getSimpleName(), null);
    }

    @org.junit.After
    public void tearDown() throws Exception {
        temp.delete();
    }

    @org.junit.Test
    public void testLoadPrivateKey() throws Exception {
        // Load private key
        KeyPair keyPair = PEMUtils.loadPrivateKey(PRIVATE_KEY);
        assertNotNull(keyPair);

        // Message
        String messageOut = "foobar";

        // Encrypt
        byte[] encryptedOut = PEMUtils.encrypt(messageOut, keyPair.getPublic(), ALGORITHM);
        assertTrue(encryptedOut.length > 0);

        // Encode
        String encodedOut = Base64.getEncoder().encodeToString(encryptedOut);
        assertNotNull(encodedOut);

        // Write
        Files.write(temp.toPath(), encodedOut.getBytes());
        assertTrue(temp.exists());

        // Read
        String encodedIn = new String(Files.readAllBytes(temp.toPath()), StandardCharsets.UTF_8);
        assertEquals(encodedIn, encodedOut);

        // Decode
        byte[] encryptedIn = Base64.getDecoder().decode(encodedIn);
        assertEquals(encryptedIn, encryptedOut);

        // Decrypt
        String messageIn = PEMUtils.decrypt(encryptedIn, keyPair.getPrivate(), ALGORITHM);
        assertEquals(messageIn, messageOut);
    }

    @org.junit.Test
    public void testLoadPublicKey() throws Exception {
        // Load private key
        KeyPair keyPair = PEMUtils.loadPrivateKey(PRIVATE_KEY);
        assertNotNull(keyPair);

        // Load public key
        PublicKey publicKey = PEMUtils.loadPublicKey(PUBLIC_KEY);
        assertNotNull(publicKey);

        // Message
        String messageOut = "foobar";

        // Encrypt
        byte[] encryptedOut = PEMUtils.encrypt(messageOut, publicKey, ALGORITHM);
        assertTrue(encryptedOut.length > 0);

        // Encode
        String encodedOut = Base64.getEncoder().encodeToString(encryptedOut);
        assertNotNull(encodedOut);

        // Write
        Files.write(temp.toPath(), encodedOut.getBytes());
        assertTrue(temp.exists());

        // Read
        String encodedIn = new String(Files.readAllBytes(temp.toPath()), StandardCharsets.UTF_8);
        assertEquals(encodedIn, encodedOut);

        // Decode
        byte[] encryptedIn = Base64.getDecoder().decode(encodedIn);
        assertEquals(encryptedIn, encryptedOut);

        // Decrypt
        String messageIn = PEMUtils.decrypt(encryptedIn, keyPair.getPrivate(), ALGORITHM);
        assertEquals(messageIn, messageOut);
    }
}