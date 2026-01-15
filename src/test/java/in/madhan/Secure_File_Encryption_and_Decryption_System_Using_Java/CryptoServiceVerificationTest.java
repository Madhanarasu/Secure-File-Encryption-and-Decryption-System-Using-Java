package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class CryptoServiceVerificationTest {

    public static void main(String[] args) throws Exception {
        System.out.println("Starting Verification...");

        Path plainFile = Files.createTempFile("plain", ".txt");
        Files.write(plainFile, "This is plain text".getBytes());

        Path encryptedFile = Files.createTempFile("encrypted", ".enc");
        char[] password = "password".toCharArray();

        try {
            // Test 1: plain file should NOT be encrypted
            if (CryptoService.isEncryptedFile(plainFile)) {
                System.out.println("FAILURE: Plain file falsely identified as encrypted.");
            } else {
                System.out.println("SUCCESS: Plain file identified as NOT encrypted.");
            }

            // Encrypt it
            CryptoService.encrypt(plainFile, encryptedFile, password);

            // Test 2: Encrypted file SHOULD be encrypted
            if (CryptoService.isEncryptedFile(encryptedFile)) {
                System.out.println("SUCCESS: Encrypted file identified correctly.");
            } else {
                System.out.println("FAILURE: Encrypted file NOT identified as encrypted.");
            }

            // Test 3: Double Encrypted file
            Path doubleEncryptedFile = Files.createTempFile("double", ".enc");
            CryptoService.encrypt(encryptedFile, doubleEncryptedFile, password);

            if (CryptoService.isEncryptedFile(doubleEncryptedFile)) {
                System.out.println("SUCCESS: Double Encrypted file identified as encrypted.");
            } else {
                System.out.println("FAILURE: Double Encrypted file NOT identified as encrypted.");
            }

            Files.deleteIfExists(doubleEncryptedFile);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            Files.deleteIfExists(plainFile);
            Files.deleteIfExists(encryptedFile);
        }
    }
}
