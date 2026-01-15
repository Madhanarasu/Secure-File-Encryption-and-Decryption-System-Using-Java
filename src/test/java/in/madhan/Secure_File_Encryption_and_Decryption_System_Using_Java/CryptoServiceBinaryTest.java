package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Random;

public class CryptoServiceBinaryTest {

    public static void main(String[] args) throws Exception {
        System.out.println("Starting Binary Reproduction...");

        // 1. Create a 1MB random binary file
        byte[] originalData = new byte[1024 * 1024]; // 1MB
        new Random().nextBytes(originalData);

        Path originalFile = Files.createTempFile("binary_orig", ".bin");
        Path encryptedFile = Files.createTempFile("binary_enc", ".enc");
        Path decryptedFile = Files.createTempFile("binary_dec", ".bin");

        char[] password = "strongpassword".toCharArray();

        try {
            Files.write(originalFile, originalData);
            System.out.println("Original binary file created: " + originalData.length + " bytes.");

            // 2. Encrypt
            System.out.println("Encrypting...");
            CryptoService.encrypt(originalFile, encryptedFile, password);
            System.out.println("Encryption done. Encrypted size: " + Files.size(encryptedFile));

            // 3. Decrypt
            System.out.println("Decrypting...");
            CryptoService.decrypt(encryptedFile, decryptedFile, password);
            System.out.println("Decryption done. Decrypted size: " + Files.size(decryptedFile));

            // 4. Compare
            byte[] decryptedData = Files.readAllBytes(decryptedFile);
            if (Arrays.equals(originalData, decryptedData)) {
                System.out.println("SUCCESS: Binary content matches perfectly.");
            } else {
                System.out.println("FAILURE: Binary content mismatch!");
                System.out.println("Original Size: " + originalData.length);
                System.out.println("Decrypted Size: " + decryptedData.length);
            }

            // 5. Test Overwrite Scenario (Input == Output)
            System.out.println("\n--- Test Overwrite Scenario ---");
            Path overwriteFile = Files.createTempFile("overwrite_test", ".enc");
            Files.copy(encryptedFile, overwriteFile, java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            try {
                // Try to decrypt overwriteFile INTO overwriteFile
                System.out.println("Decrypting with same input and output path...");
                CryptoService.decrypt(overwriteFile, overwriteFile, password);

                // If we get here, check content
                if (Files.size(overwriteFile) == 0) {
                    System.out.println("CRITICAL: File was truncated to 0 bytes!");
                } else {
                    System.out.println("File size after overwrite: " + Files.size(overwriteFile));
                    byte[] content = Files.readAllBytes(overwriteFile);
                    if (Arrays.equals(originalData, content)) {
                        System.out.println("MIRACLE: Overwrite worked (this is unexpected for streams).");
                    } else {
                        System.out.println("RESULT: File corrupted/changed but not empty.");
                    }
                }
            } catch (Exception e) {
                System.out.println("Exception during overwrite: " + e.getMessage());
                // E.g. "Input stream mismatch" because header was truncated before read?
            }
            Files.deleteIfExists(overwriteFile);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            Files.deleteIfExists(originalFile);
            Files.deleteIfExists(encryptedFile);
            Files.deleteIfExists(decryptedFile);
        }
    }
}
