package in.madhan.Secure_File_Encryption_and_Decryption_System_Using_Java;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class DBController {

    private static Connection con = null;

    // Use a relative path for portability. This creates 'FileGuardian.db' in the
    // process working directory.
    private static final String DB_URL = "jdbc:sqlite:FileGuardian.db";

    public static synchronized Connection connect() {
        try {
            if (con != null && !con.isClosed()) {
                return con;
            }
            con = DriverManager.getConnection(DB_URL);
            initializeDB(con);
        } catch (SQLException e) {
            System.out.println("Connection failed: " + e.getMessage());
        }
        return con;
    }

    private static void initializeDB(Connection conn) throws SQLException {
        // Create Users table
        try (Statement stmt = conn.createStatement()) {
            String createUsers = "CREATE TABLE IF NOT EXISTS Users (" +
                    "Username TEXT PRIMARY KEY, " +
                    "Password TEXT NOT NULL)";
            stmt.execute(createUsers);

            // Create Logs table
            String createLogs = "CREATE TABLE IF NOT EXISTS Logs (" +
                    "LogId INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "Username TEXT, " +
                    "Action TEXT, " +
                    "Filename TEXT, " +
                    "Timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)";
            stmt.execute(createLogs);

            // Check if admin exists
            try (ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM Users")) {
                if (rs.next() && rs.getInt(1) == 0) {
                    // Seed default admin
                    registerUser("admin", "Password@123");
                    System.out.println("Default admin user created.");
                }
            }
        }
    }

    public static boolean registerUser(String username, String rawPassword) {
        String hashedPassword = CryptoService.hashPassword(rawPassword);
        String sql = "INSERT INTO Users(Username, Password) VALUES(?,?)";

        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.out.println("Registration failed: " + e.getMessage());
            return false;
        }
    }

    public static boolean validateUser(String username, String rawPassword) {
        String sql = "SELECT Password FROM Users WHERE Username = ?";
        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    String storedHash = rs.getString("Password");
                    // Check if it's a legacy cleartext password (no salt separator)
                    // If so, and it matches, we should upgrade it (omitted for now), or just accept
                    // if simple match
                    // But our new admin is hashed.
                    // Let's assume storedHash is the hash.
                    // If the project had old plain text passwords, this might break them unless we
                    // check.
                    // Simple check: does it contain ':'?
                    if (storedHash.contains(":")) {
                        return CryptoService.verifyPassword(rawPassword, storedHash);
                    } else {
                        // Fallback for legacy plain text
                        return storedHash.equals(rawPassword);
                    }
                }
            }
        } catch (SQLException e) {
            System.out.println("Validation failed: " + e.getMessage());
        }
        return false;
    }

    public static void logActivity(String username, String action, String filename) {
        String sql = "INSERT INTO Logs(Username, Action, Filename) VALUES(?,?,?)";
        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            pstmt.setString(2, action);
            pstmt.setString(3, filename);
            pstmt.executeUpdate();
        } catch (SQLException e) {
            System.out.println("Logging failed: " + e.getMessage());
        }
    }

    public static List<String> getLogs(String username) {
        List<String> logs = new ArrayList<>();
        String sql = "SELECT Action, Filename, Timestamp FROM Logs WHERE Username = ? ORDER BY Timestamp DESC";
        try (Connection conn = connect();
                PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    logs.add(String.format("[%s] %s: %s", rs.getString("Timestamp"), rs.getString("Action"),
                            rs.getString("Filename")));
                }
            }
        } catch (SQLException e) {
            logs.add("Error retrieving logs: " + e.getMessage());
        }
        return logs;
    }
}