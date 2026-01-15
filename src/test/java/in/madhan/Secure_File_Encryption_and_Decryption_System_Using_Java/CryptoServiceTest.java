package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import junit.framework.TestCase;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class CryptoServiceTest extends TestCase {

    public void testEncryptionDecryption() throws Exception {
        String originalContent = "Hello World! This is a test for encryption and decryption.";
        char[] password = "password123".toCharArray();

        Path originalFile = Files.createTempFile("original", ".txt");
        Path encryptedFile = Files.createTempFile("encrypted", ".enc");
        Path decryptedFile = Files.createTempFile("decrypted", ".txt");

        try {
            // Write original content
            Files.write(originalFile, originalContent.getBytes("UTF-8"));

            // Encrypt
            CryptoService.encrypt(originalFile, encryptedFile, password);

            // Decrypt
            CryptoService.decrypt(encryptedFile, decryptedFile, password);

            // Read decrypted content
            byte[] decryptedBytes = Files.readAllBytes(decryptedFile);
            String decryptedContent = new String(decryptedBytes, "UTF-8");

            assertEquals("Decrypted content should match original", originalContent, decryptedContent);

            // Check that encrypted file is different (basic check)
            byte[] encryptedBytes = Files.readAllBytes(encryptedFile);
            assertFalse("Encrypted content should not match original",
                    Arrays.equals(encryptedBytes, originalContent.getBytes("UTF-8")));

        } finally {
            Files.deleteIfExists(originalFile);
            Files.deleteIfExists(encryptedFile);
            Files.deleteIfExists(decryptedFile);
        }
    }
}
