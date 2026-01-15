package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class CryptoServiceReproduction {

    public static void main(String[] args) throws Exception {
        System.out.println("Starting Reproduction...");
        String originalContent = "Hello World! This is a test for encryption and decryption.";
        char[] password = "password123".toCharArray();

        Path originalFile = Files.createTempFile("original", ".txt");
        Path encryptedFile = Files.createTempFile("encrypted", ".enc");
        Path decryptedFile = Files.createTempFile("decrypted", ".txt");

        try {
            // Write original content
            Files.write(originalFile, originalContent.getBytes("UTF-8"));
            System.out.println("Original file created.");

            // Encrypt
            System.out.println("Encrypting...");
            CryptoService.encrypt(originalFile, encryptedFile, password);
            System.out.println("Encryption done.");

            // Decrypt
            System.out.println("Decrypting...");
            CryptoService.decrypt(encryptedFile, decryptedFile, password);
            System.out.println("Decryption done.");

            // Read decrypted content
            byte[] decryptedBytes = Files.readAllBytes(decryptedFile);
            String decryptedContent = new String(decryptedBytes, "UTF-8");

            if (originalContent.equals(decryptedContent)) {
                System.out.println("SUCCESS: Decrypted content matches original.");
            } else {
                System.out.println("FAILURE: Decrypted content does NOT match original.");
                System.out.println("Expected: " + originalContent);
                System.out.println("Actual:   " + decryptedContent);

                // Debugging: Print hex of actual
                System.out.println("Actual Hex: " + bytesToHex(decryptedBytes));
            }

            // Check that encrypted file is different (basic check)
            byte[] encryptedBytes = Files.readAllBytes(encryptedFile);
            if (Arrays.equals(encryptedBytes, originalContent.getBytes("UTF-8"))) {
                System.out.println("WARNING: Encrypted content matches original (Encryption failed?)");
            } else {
                System.out.println("Verified: Encrypted content is different from original.");
            }

            // --- TEST CASE 2: Wrong Password ---
            System.out.println("\n--- Test 2: Wrong Password ---");
            Path wrongPassFile = Files.createTempFile("wrongpass", ".txt");
            try {
                char[] wrongPass = "wrongpassword".toCharArray();
                CryptoService.decrypt(encryptedFile, wrongPassFile, wrongPass);
                System.out.println("WARNING: Decryption should have failed with wrong password but didn't throw!");
            } catch (Exception e) {
                System.out.println("Caught expected exception: " + e.getMessage());
            }

            if (Files.exists(wrongPassFile) && Files.size(wrongPassFile) > 0) {
                System.out.println(
                        "WARNING: Output file has content on failure: " + Files.size(wrongPassFile) + " bytes.");
            } else {
                System.out.println("Verified: Output file is empty on failure.");
            }
            Files.deleteIfExists(wrongPassFile);

            // --- TEST CASE 3: Corrupted File ---
            System.out.println("\n--- Test 3: Corrupted File ---");
            Path corruptFile = Files.createTempFile("corrupt", ".enc");
            Path corruptOutFile = Files.createTempFile("corrupt_out", ".txt");
            byte[] encBytes = Files.readAllBytes(encryptedFile);
            // Flip a bit in the data (after header 4 + salt 16 + iv 12 = 32 bytes)
            if (encBytes.length > 35) {
                encBytes[35] ^= 0x01;
            }
            Files.write(corruptFile, encBytes);

            try {
                CryptoService.decrypt(corruptFile, corruptOutFile, password);
                System.out.println("WARNING: Decryption should have failed with corrupted file but didn't throw!");
            } catch (Exception e) {
                System.out.println("Caught expected exception: " + e.getMessage());
            }

            if (Files.exists(corruptOutFile) && Files.size(corruptOutFile) > 0) {
                System.out.println(
                        "WARNING: Output file has content on corruption: " + Files.size(corruptOutFile) + " bytes.");
            } else {
                System.out.println("Verified: Output file is empty on corruption.");
            }

            Files.deleteIfExists(corruptFile);
            Files.deleteIfExists(corruptOutFile);

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            Files.deleteIfExists(originalFile);
            Files.deleteIfExists(encryptedFile);
            Files.deleteIfExists(decryptedFile);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
