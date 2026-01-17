package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.util.Arrays;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoService {
    // PBKDF2 parameters
    private static final int SALT_LENGTH = 16; // bytes
    private static final int GCM_IV_LENGTH = 12; // bytes
    private static final int CBC_IV_LENGTH = 16; // bytes
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256; // bits

    private static final String MAGIC_V1 = "FG01"; // Legacy (GCM)
    private static final String MAGIC_V2 = "FG02"; // Version 2 (Support Modes)
    private static final String MAGIC_V3 = "FG03"; // Version 3 (Mode + Metadata)

    public enum EncryptionMode {
        GCM, CBC
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    public static void encrypt(Path inputFile, Path outputFile, char[] password, EncryptionMode mode)
            throws IOException, GeneralSecurityException {

        Path targetInput = inputFile;
        boolean isDir = Files.isDirectory(inputFile);
        Path tempZip = null;

        if (isDir) {
            // Zip the folder first
            tempZip = Files.createTempFile("folder_enc", ".zip");
            zipFolder(inputFile, tempZip);
            targetInput = tempZip;
        }

        try {
            byte[] salt = new byte[SALT_LENGTH];
            RANDOM.nextBytes(salt);
            SecretKey key = deriveKey(password, salt);

            int ivLength = (mode == EncryptionMode.GCM) ? GCM_IV_LENGTH : CBC_IV_LENGTH;
            byte[] iv = new byte[ivLength];
            RANDOM.nextBytes(iv);

            Cipher cipher;
            if (mode == EncryptionMode.GCM) {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            } else {
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec spec = new IvParameterSpec(iv);
                cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            }

            // Prepare Metadata (Extension)
            // If it was a folder, we are encrypting a .zip, so original extension is ".zip"
            // However, to signal it was a folder, maybe we rely on the fact that when we
            // decrypt .zip, we unzip it?
            // Yes.
            String fileName = targetInput.getFileName().toString();
            // If it was a folder "MyData", we zipped to "temp.zip".
            // We want the decrypted name to "MyData.zip" so we can unzip it to "MyData".
            // So if isDir, let's treat extension as ".zip" and base name as original folder
            // name logic?
            // Actually, simply:
            // Input: "MyData" (Folder) -> Zipped to: "temp123.zip".
            // We want extension to be ".zip".
            // But we want the preserved name to be "MyData.zip" so when decrypting we get
            // "MyData.zip".

            String extension = "";
            if (isDir) {
                extension = ".zip";
            } else {
                String rawName = inputFile.getFileName().toString();
                int i = rawName.lastIndexOf('.');
                if (i > 0)
                    extension = rawName.substring(i);
            }

            byte[] extBytes = extension.getBytes("UTF-8");
            if (extBytes.length > 255)
                throw new IOException("Extension too long");

            // Write Header: MAGIC_V3 (4) + Mode (1) + Salt (16) + IV (Var) + ExtLen(1) +
            // ExtBytes
            try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(targetInput));
                    BufferedOutputStream out = new BufferedOutputStream(Files.newOutputStream(outputFile))) {

                out.write(MAGIC_V3.getBytes("UTF-8"));
                out.write(mode == EncryptionMode.GCM ? 0 : 1);
                out.write(salt);
                out.write(iv);
                out.write(extBytes.length); // 1 byte length
                out.write(extBytes);

                try (CipherOutputStream cos = new CipherOutputStream(out, cipher)) {
                    byte[] buffer = new byte[4096];
                    int r;
                    while ((r = in.read(buffer)) != -1) {
                        cos.write(buffer, 0, r);
                    }
                    cos.flush();
                }
            }
        } finally {
            // Cleanup temp zip
            if (tempZip != null)
                Files.deleteIfExists(tempZip);
        }
    }

    public static boolean isEncrypted(Path inputFile) {
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile))) {
            byte[] magicBytes = new byte[4];
            if (in.read(magicBytes) != 4) {
                return false;
            }
            String magic = new String(magicBytes, "UTF-8");
            return MAGIC_V1.equals(magic) || MAGIC_V2.equals(magic) || MAGIC_V3.equals(magic);
        } catch (IOException e) {
            return false;
        }
    }

    public static String getDecryptedName(Path inputFile) {
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile))) {
            byte[] magicBytes = new byte[4];
            if (in.read(magicBytes) != 4)
                return null;
            String magic = new String(magicBytes, "UTF-8");

            if (MAGIC_V3.equals(magic)) {
                int modeByte = in.read();
                int ivLength = (modeByte == 0) ? GCM_IV_LENGTH : CBC_IV_LENGTH;

                long skipped = in.skip(SALT_LENGTH + ivLength);
                if (skipped != SALT_LENGTH + ivLength)
                    return null;

                int extLen = in.read();
                if (extLen > 0) {
                    byte[] extBytes = new byte[extLen];
                    if (in.read(extBytes) == extLen) {
                        String ext = new String(extBytes, "UTF-8");
                        String currentName = inputFile.getFileName().toString();
                        String base = currentName;
                        if (currentName.toLowerCase().endsWith(".enc"))
                            base = currentName.substring(0, currentName.length() - 4);
                        else if (currentName.toLowerCase().endsWith(".encrypted"))
                            base = currentName.substring(0, currentName.length() - 10);

                        // Avoid duplication
                        if (!base.toLowerCase().endsWith(ext.toLowerCase())) {
                            return base + ext;
                        }
                        return base;
                    }
                }
            }
        } catch (IOException e) {
        }

        String name = inputFile.getFileName().toString();
        if (name.toLowerCase().endsWith(".enc"))
            return name.substring(0, name.length() - 4);
        if (name.toLowerCase().endsWith(".encrypted"))
            return name.substring(0, name.length() - 10);
        return name + ".decrypted";
    }

    public static void decrypt(Path inputFile, Path outputFile, char[] password)
            throws IOException, GeneralSecurityException {

        Path actualOutput = outputFile;
        boolean processingInPlace = inputFile.toAbsolutePath().normalize()
                .equals(outputFile.toAbsolutePath().normalize());

        if (processingInPlace) {
            actualOutput = outputFile
                    .resolveSibling(outputFile.getFileName().toString() + ".tmp_" + System.currentTimeMillis());
        }

        try {
            doDecrypt(inputFile, actualOutput, password);

            if (processingInPlace) {
                Files.move(actualOutput, outputFile, StandardCopyOption.REPLACE_EXISTING);
                actualOutput = outputFile; // Update ref to final location
            }

            // Check if it's a zip and auto-unzip
            if (actualOutput.toString().toLowerCase().endsWith(".zip")) {
                // Determine folder name (remove .zip)
                String zipName = actualOutput.getFileName().toString();
                String folderName = zipName.substring(0, zipName.length() - 4);
                Path destFolder = actualOutput.resolveSibling(folderName);

                // If dest folder exists, maybe backup or overwrite? Let's just unzip.
                // Or maybe unzip to "FolderName_Unzipped" if exists?
                // For now, standard unzip.
                unzip(actualOutput, destFolder);

                // Optional: Delete the zip after successful unzip?
                // User said "Decryption will unzip it back". Usually implies getting the folder
                // back.
                // Let's delete the intermediate zip to make it clean.
                Files.delete(actualOutput);
            }

        } catch (Exception e) {
            if (processingInPlace && Files.exists(actualOutput) && !actualOutput.equals(outputFile)) {
                Files.delete(actualOutput);
            }
            throw e;
        }
    }

    private static void doDecrypt(Path inputFile, Path outputFile, char[] password)
            throws IOException, GeneralSecurityException {
        try (BufferedInputStream in = new BufferedInputStream(Files.newInputStream(inputFile))) {
            byte[] magicBytes = new byte[4];
            if (in.read(magicBytes) != 4)
                throw new IOException("Invalid file format (header too short)");
            String magic = new String(magicBytes, "UTF-8");

            EncryptionMode mode = EncryptionMode.GCM;
            int ivLength = GCM_IV_LENGTH;

            if (MAGIC_V1.equals(magic)) {
                mode = EncryptionMode.GCM;
                ivLength = GCM_IV_LENGTH;
            } else if (MAGIC_V2.equals(magic)) {
                int modeByte = in.read();
                if (modeByte == 0)
                    mode = EncryptionMode.GCM;
                else if (modeByte == 1) {
                    mode = EncryptionMode.CBC;
                    ivLength = CBC_IV_LENGTH;
                } else
                    throw new IOException("Unknown encryption mode");
            } else if (MAGIC_V3.equals(magic)) {
                int modeByte = in.read();
                if (modeByte == 0)
                    mode = EncryptionMode.GCM;
                else if (modeByte == 1) {
                    mode = EncryptionMode.CBC;
                    ivLength = CBC_IV_LENGTH;
                } else
                    throw new IOException("Unknown encryption mode");
            } else
                throw new IOException("Invalid file format (magic mismatch)");

            byte[] salt = new byte[SALT_LENGTH];
            if (in.read(salt) != SALT_LENGTH)
                throw new IOException("Invalid file format (salt)");

            byte[] iv = new byte[ivLength];
            if (in.read(iv) != ivLength)
                throw new IOException("Invalid file format (iv)");

            if (MAGIC_V3.equals(magic)) {
                int extLen = in.read();
                if (extLen > 0) {
                    long skipped = in.skip(extLen);
                    if (skipped != extLen)
                        throw new IOException("Invalid file format (ext)");
                }
            }

            SecretKey key = deriveKey(password, salt);
            Cipher cipher;
            if (mode == EncryptionMode.GCM) {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
            } else {
                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                IvParameterSpec spec = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, key, spec);
            }

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

    // Zip Utility
    private static void zipFolder(Path sourceFolderPath, Path zipPath) throws IOException {
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipPath.toFile()))) {
            Files.walkFileTree(sourceFolderPath, new SimpleFileVisitor<Path>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    zos.putNextEntry(new ZipEntry(sourceFolderPath.relativize(file).toString()));
                    Files.copy(file, zos);
                    zos.closeEntry();
                    return FileVisitResult.CONTINUE;
                }
            });
        }
    }

    // Unzip Utility
    private static void unzip(Path zipFilePath, Path destDirectory) throws IOException {
        if (!Files.exists(destDirectory)) {
            Files.createDirectories(destDirectory);
        }
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath.toFile()))) {
            ZipEntry zipEntry = zis.getNextEntry();
            while (zipEntry != null) {
                Path newPath = destDirectory.resolve(zipEntry.getName()).normalize();
                if (!newPath.startsWith(destDirectory)) {
                    // Zip Slip vulnerability protection
                    throw new IOException("Zip entry is outside of the target dir: " + zipEntry.getName());
                }
                if (zipEntry.isDirectory()) {
                    Files.createDirectories(newPath);
                } else {
                    if (newPath.getParent() != null)
                        Files.createDirectories(newPath.getParent());
                    try (BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(newPath.toFile()))) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            bos.write(buffer, 0, len);
                        }
                    }
                }
                zipEntry = zis.getNextEntry();
            }
            zis.closeEntry();
        }
    }

    // Secure File Shredder
    public static void shredFile(Path file) throws IOException {
        if (!Files.exists(file))
            return;

        // Pass 1: Random data
        try (RandomAccessFile raf = new RandomAccessFile(file.toFile(), "rw")) {
            long length = raf.length();
            byte[] buffer = new byte[4096];
            long pos = 0;
            while (pos < length) {
                RANDOM.nextBytes(buffer);
                int writeLen = (int) Math.min(buffer.length, length - pos);
                raf.write(buffer, 0, writeLen);
                pos += writeLen;
            }
            raf.getFD().sync(); // Force write to disk

            // Pass 2: Zeros
            raf.seek(0);
            pos = 0;
            Arrays.fill(buffer, (byte) 0);
            while (pos < length) {
                int writeLen = (int) Math.min(buffer.length, length - pos);
                raf.write(buffer, 0, writeLen);
                pos += writeLen;
            }
            raf.getFD().sync();
        }

        // Pass 3: Delete
        Files.delete(file);
    }
}