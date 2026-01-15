package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoService {
    // PBKDF2 parameters
    private static final int SALT_LENGTH = 16; // bytes
    private static final int IV_LENGTH = 12; // bytes for GCM
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256; // bits
    private static final String MAGIC = "FG01"; // 4 bytes header

    private static final SecureRandom RANDOM = new SecureRandom();

    public static void encrypt(Path inputFile, Path outputFile, char[] password)
            throws IOException, GeneralSecurityException {
        byte[] salt = new byte[SALT_LENGTH];
        RANDOM.nextBytes(salt);
        SecretKey key = deriveKey(password, salt);

        byte[] iv = new byte[IV_LENGTH];
        RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        // Write header: MAGIC (4) + salt (16) + iv (12)
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile));
                BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outputFile))) {

            out.write(MAGIC.getBytes("UTF-8"));
            out.write(salt);
            out.write(iv);

            try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
                byte[] buffer = new byte[4096];
                int r;
                while ((r = in.read(buffer)) != -1) {
                    cos.write(buffer, 0, r);
                }
                cos.flush();
            }
        }
    }

    public static void decrypt(Path inputFile, Path outputFile, char[] password)
            throws IOException, GeneralSecurityException {
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile))) {
            byte[] magicBytes = new byte[MAGIC.length()];
            if (in.read(magicBytes) != magicBytes.length) {
                throw new IOException("Invalid file format (header too short)");
            }
            String magic = new String(magicBytes, "UTF-8");
            if (!MAGIC.equals(magic)) {
                throw new IOException("Invalid file format (magic mismatch)");
            }

            byte[] salt = new byte[SALT_LENGTH];
            if (in.read(salt) != SALT_LENGTH) {
                throw new IOException("Invalid file format (salt)");
            }
            byte[] iv = new byte[IV_LENGTH];
            if (in.read(iv) != IV_LENGTH) {
                throw new IOException("Invalid file format (iv)");
            }

            SecretKey key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);

            try (CipherInputStream cis = new CipherInputStream(in, cipher);
                    BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outputFile))) {
                byte[] buffer = new byte[4096];
                int r;
                while ((r = cis.read(buffer)) != -1) {
                    out.write(buffer, 0, r);
                }
                out.flush();
            }
        }
    }

    private static SecretKey deriveKey(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static String hashPassword(String password) {
        try {
            byte[] salt = new byte[SALT_LENGTH];
            RANDOM.nextBytes(salt);
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            return java.util.Base64.getEncoder().encodeToString(salt) + ":"
                    + java.util.Base64.getEncoder().encodeToString(hash);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    public static boolean verifyPassword(String password, String storedHash) {
        try {
            String[] parts = storedHash.split(":");
            if (parts.length != 2)
                return false;
            byte[] salt = java.util.Base64.getDecoder().decode(parts[0]);
            byte[] hash = java.util.Base64.getDecoder().decode(parts[1]);

            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] testHash = skf.generateSecret(spec).getEncoded();

            return java.util.Arrays.equals(hash, testHash);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    public static boolean isEncryptedFile(Path file) {
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(file))) {
            byte[] magicBytes = new byte[MAGIC.length()];
            if (in.read(magicBytes) != magicBytes.length) {
                return false;
            }
            String magic = new String(magicBytes, "UTF-8");
            return MAGIC.equals(magic);
        } catch (IOException e) {
            return false;
        }
    }
}