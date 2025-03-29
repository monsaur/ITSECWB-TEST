package Controller;

import Model.History;
import Model.Logs;
import Model.Product;
import Model.User;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.sql.*;  
import java.sql.PreparedStatement; 

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;
import java.sql.PreparedStatement;
import java.sql.Timestamp;
import java.util.Date;

public class SQLite {
    
    public int DEBUG_MODE = 0;
    String driverURL = "jdbc:sqlite:" + "database.db";
    
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 128;
    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    
    private String hashPassword(String password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    private byte[] generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
    
    // Method to validate if a username exists
    public boolean usernameExists(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getInt(1) > 0;
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }
    
    public void createNewDatabase() {
        try (Connection conn = DriverManager.getConnection(driverURL)) {
            if (conn != null) {
                DatabaseMetaData meta = conn.getMetaData();
                System.out.println("Database database.db created.");
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void enableWALMode() {
        String query = "PRAGMA journal_mode=WAL;";

        try (Connection conn = DriverManager.getConnection(driverURL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(query);
            System.out.println("✅ SQLite WAL mode enabled!");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    public void createHistoryTable() {
        String sql = "CREATE TABLE IF NOT EXISTS history (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " username TEXT NOT NULL,\n"
            + " name TEXT NOT NULL,\n"
            + " stock INTEGER DEFAULT 0,\n"
            + " timestamp TEXT NOT NULL\n"
            + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table history in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void createLogsTable() {
        String sql = "CREATE TABLE IF NOT EXISTS logs (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " event TEXT NOT NULL,\n"
            + " username TEXT NOT NULL,\n"
            + " desc TEXT NOT NULL,\n"
            + " timestamp TEXT NOT NULL\n"
            + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table logs in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
     
    public void createProductTable() {
        String sql = "CREATE TABLE IF NOT EXISTS product (\n"
            + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
            + " name TEXT NOT NULL UNIQUE,\n"
            + " stock INTEGER DEFAULT 0,\n"
            + " price REAL DEFAULT 0.00\n"
            + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table product in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
             System.out.println("❌ ERROR creating `users` table: " + ex.getMessage());
        }
    }
     
    public void createUserTable() {
        String sql = "CREATE TABLE IF NOT EXISTS users (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " username TEXT NOT NULL UNIQUE,\n"
                + " password TEXT NOT NULL,\n"
                + " salt TEXT NOT NULL,\n"
                + " role INTEGER DEFAULT 2,\n"
                + " failed_attempts INTEGER DEFAULT 0,\n"
                + " locked INTEGER DEFAULT 0\n"
                + ");";

        try (Connection conn = DriverManager.getConnection(driverURL);
             Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table users in database.db created.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropHistoryTable() {
        String sql = "DROP TABLE IF EXISTS history;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table history in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropLogsTable() {
        String sql = "DROP TABLE IF EXISTS logs;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table logs in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropProductTable() {
        String sql = "DROP TABLE IF EXISTS product;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table product in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public void dropUserTable() {
        String sql = "DROP TABLE IF EXISTS users;";

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()) {
            stmt.execute(sql);
            System.out.println("Table users in database.db dropped.");
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public boolean addHistory(String username, String name, int stock, String timestamp) {
        // Validate inputs
        if (!InputValidator.isValidUsername(username) || !InputValidator.isValidProductName(name) || stock <= 0) {
            return false;
        }
        
        String sql = "INSERT INTO history(username, name, stock, timestamp) VALUES(?, ?, ?, ?)";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            pstmt.setString(2, name);
            pstmt.setInt(3, stock);
            pstmt.setString(4, timestamp);
            
            pstmt.executeUpdate();
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    public boolean addLogs(String event, String username, String desc, String timestamp) {
        String sql = "INSERT INTO logs(event, username, desc, timestamp) VALUES(?, ?, ?, ?)";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, event);
            pstmt.setString(2, username);
            pstmt.setString(3, desc);
            pstmt.setString(4, timestamp);
            
            pstmt.executeUpdate();
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    public boolean addProduct(String name, int stock, double price) {
        // Validate inputs
        if (!InputValidator.isValidProductName(name) || stock < 0 || price < 0) {
            return false;
        }
        
        String sql = "INSERT INTO product(name, stock, price) VALUES(?, ?, ?)";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, name);
            pstmt.setInt(2, stock);
            pstmt.setDouble(3, price);
            
            pstmt.executeUpdate();
            
            // Add log entry
            addLogs("PRODUCT", "SYSTEM", "Product added: " + name, new Timestamp(new Date().getTime()).toString());
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    public boolean addUser(String username, String password) {
        // Validate inputs
        if (!InputValidator.isValidUsername(username) || !InputValidator.isValidPassword(password)) {
            return false;
        }

        // Check if username already exists
        if (usernameExists(username)) {
            return false;
        }

        String sql = "INSERT INTO users(username, password, salt, role, failed_attempts, locked) VALUES(?, ?, ?, ?, ?, ?)";

        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(password, salt);
            String saltStr = Base64.getEncoder().encodeToString(salt);

            pstmt.setString(1, username);
            pstmt.setString(2, hashedPassword);
            pstmt.setString(3, saltStr);
            pstmt.setInt(4, 2); // Default role is CLIENT
            pstmt.setInt(5, 0); // No failed attempts
            pstmt.setInt(6, 0); // Not locked

            pstmt.executeUpdate();

            // Add log entry
            addLogs("NOTICE", username, "User registration successful", new Timestamp(new Date().getTime()).toString());
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    // Method to change a user's password with proper validation
    public boolean changePassword(String username, String newPassword) {
        // Validate inputs
        if (!InputValidator.isValidUsername(username) || !InputValidator.isValidPassword(newPassword)) {
            return false;
        }

        String sql = "UPDATE users SET password = ?, salt = ? WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            byte[] salt = generateSalt();
            String hashedPassword = hashPassword(newPassword, salt);
            String saltStr = Base64.getEncoder().encodeToString(salt);

            pstmt.setString(1, hashedPassword);
            pstmt.setString(2, saltStr);
            pstmt.setString(3, username);

            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected > 0) {
                addLogs("NOTICE", username, "Password changed successfully", new Timestamp(new Date().getTime()).toString());
                return true;
            }
            return false;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    // Method to update a user's role
    public boolean updateUserRole(String username, int newRole) {
        // Validate inputs
        if (!InputValidator.isValidUsername(username) || newRole < 1 || newRole > 5) {
            return false;
        }

        String sql = "UPDATE users SET role = ? WHERE username = ?";

        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, newRole);
            pstmt.setString(2, username);

            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected > 0) {
                addLogs("NOTICE", username, "User role updated to " + newRole, new Timestamp(new Date().getTime()).toString());
                return true;
            }
            return false;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    // Method to toggle user lock status
    public boolean toggleUserLock(String username) {
        // Validate username
        if (!InputValidator.isValidUsername(username)) {
            return false;
        }

        // First, check current lock status
        String checkSql = "SELECT locked FROM users WHERE username = ?";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            
            checkStmt.setString(1, username);
            ResultSet rs = checkStmt.executeQuery();
            
            if (rs.next()) {
                int currentStatus = rs.getInt("locked");
                int newStatus = (currentStatus == 1) ? 0 : 1;
                
                // Now update the lock status
                String updateSql = "UPDATE users SET locked = ?, failed_attempts = ? WHERE username = ?";
                
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setInt(1, newStatus);
                    updateStmt.setInt(2, 0); // Reset failed attempts
                    updateStmt.setString(3, username);
                    
                    int rowsAffected = updateStmt.executeUpdate();
                    
                    if (rowsAffected > 0) {
                        String action = (newStatus == 1) ? "locked" : "unlocked";
                        addLogs("NOTICE", username, "User account " + action, new Timestamp(new Date().getTime()).toString());
                        return true;
                    }
                }
            }
            return false;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    
    // Method to update a product
    public boolean updateProduct(String name, int stock, double price) {
        // Validate inputs
        if (!InputValidator.isValidProductName(name) || stock < 0 || price < 0) {
            return false;
        }
        
        String sql = "UPDATE product SET stock = ?, price = ? WHERE name = ?";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setInt(1, stock);
            pstmt.setDouble(2, price);
            pstmt.setString(3, name);
            
            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected > 0) {
                addLogs("PRODUCT", "SYSTEM", "Product updated: " + name, new Timestamp(new Date().getTime()).toString());
                return true;
            }
            return false;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    // Method to delete a product
    public boolean deleteProduct(String name) {
        // Validate input
        if (!InputValidator.isValidProductName(name)) {
            return false;
        }
        
        String sql = "DELETE FROM product WHERE name = ?";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, name);
            
            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected > 0) {
                addLogs("PRODUCT", "SYSTEM", "Product deleted: " + name, new Timestamp(new Date().getTime()).toString());
                return true;
            }
            return false;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    // Method to purchase a product
    public boolean purchaseProduct(String username, String productName, int quantity) {
        // Validate inputs
        if (!InputValidator.isValidUsername(username) || !InputValidator.isValidProductName(productName) || quantity <= 0) {
            return false;
        }

        // First check if product exists and has enough stock
        Product product = getProduct(productName);
        if (product == null || product.getStock() < quantity) {
            return false;
        }

        Connection conn = null;
        PreparedStatement updateStmt = null;
        PreparedStatement historyStmt = null;
        PreparedStatement logStmt = null;

        try {
            // Get a single connection for the entire transaction
            conn = DriverManager.getConnection(driverURL);

            // Start transaction - disable auto-commit
            conn.setAutoCommit(false);

            // 1. Update product stock
            String updateSql = "UPDATE product SET stock = stock - ? WHERE name = ? AND stock >= ?";
            updateStmt = conn.prepareStatement(updateSql);
            updateStmt.setInt(1, quantity);
            updateStmt.setString(2, productName);
            updateStmt.setInt(3, quantity);

            int rowsAffected = updateStmt.executeUpdate();
            if (rowsAffected == 0) {
                // Not enough stock or product doesn't exist
                conn.rollback();
                return false;
            }

            // 2. Add to history - use the same connection
            String timestamp = new Timestamp(new Date().getTime()).toString();
            String historySql = "INSERT INTO history(username, name, stock, timestamp) VALUES(?, ?, ?, ?)";
            historyStmt = conn.prepareStatement(historySql);
            historyStmt.setString(1, username);
            historyStmt.setString(2, productName);
            historyStmt.setInt(3, quantity);
            historyStmt.setString(4, timestamp);
            historyStmt.executeUpdate();

            // 3. Add log entry - use the same connection
            String logSql = "INSERT INTO logs(event, username, desc, timestamp) VALUES(?, ?, ?, ?)";
            logStmt = conn.prepareStatement(logSql);
            logStmt.setString(1, "PURCHASE");
            logStmt.setString(2, username);
            logStmt.setString(3, "Purchased " + quantity + " of " + productName);
            logStmt.setString(4, timestamp);
            logStmt.executeUpdate();

            // Commit transaction
            conn.commit();
            return true;

        } catch (SQLException ex) {
            try {
                if (conn != null) {
                    conn.rollback();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
            ex.printStackTrace();
            return false;

        } finally {
            try {
                // Close all resources
                if (updateStmt != null) updateStmt.close();
                if (historyStmt != null) historyStmt.close();
                if (logStmt != null) logStmt.close();

                // Re-enable auto-commit before closing
                if (conn != null) {
                    conn.setAutoCommit(true);
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
    }
    
    public ArrayList<History> getHistory(){
        String sql = "SELECT id, username, name, stock, timestamp FROM history";
        ArrayList<History> histories = new ArrayList<History>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            
            while (rs.next()) {
                histories.add(new History(rs.getInt("id"),
                                   rs.getString("username"),
                                   rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
        return histories;
    }
    
    public ArrayList<Logs> getLogs(){
        String sql = "SELECT id, event, username, desc, timestamp FROM logs";
        ArrayList<Logs> logs = new ArrayList<Logs>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            
            while (rs.next()) {
                logs.add(new Logs(rs.getInt("id"),
                                   rs.getString("event"),
                                   rs.getString("username"),
                                   rs.getString("desc"),
                                   rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return logs;
    }
    
    public ArrayList<Product> getProduct(){
        String sql = "SELECT id, name, stock, price FROM product";
        ArrayList<Product> products = new ArrayList<Product>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            
            while (rs.next()) {
                products.add(new Product(rs.getInt("id"),
                                   rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getFloat("price")));
            }
        } catch (Exception ex) {
            System.out.print(ex);
        }
        return products;
    }
    
    public ArrayList<User> getUsers(){
        String sql = "SELECT id, username, password, salt, role, locked FROM users";
        ArrayList<User> users = new ArrayList<User>();

        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){

            while (rs.next()) {
                users.add(new User(rs.getInt("id"),
                                   rs.getString("username"),
                                   rs.getString("password"),
                                   rs.getString("salt"),
                                   rs.getInt("role"),
                                   rs.getInt("locked")));
            }
        } catch (Exception ex) {}
        return users;
    }
    
    public void addUser(String username, String password, int role) {
        String sql = "INSERT INTO users(username,password,role) VALUES('" + username + "','" + password + "','" + role + "')";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement()){
            stmt.execute(sql);
            
        } catch (Exception ex) {
            System.out.print(ex);
        }
    }
    
    public boolean removeUser(String username) {
        // Validate input
        if (!InputValidator.isValidUsername(username)) {
            return false;
        }
        
        String sql = "DELETE FROM users WHERE username = ?";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            
            int rowsAffected = pstmt.executeUpdate();
            
            if (rowsAffected > 0) {
                addLogs("USER", "SYSTEM", "User deleted: " + username, new Timestamp(new Date().getTime()).toString());
                return true;
            }
            return false;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    public boolean clearLogs() {
        String sql = "DELETE FROM logs";
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             Statement stmt = conn.createStatement()) {
            
            stmt.execute(sql);
            
            // Add a log entry about clearing logs
            addLogs("SYSTEM", "SYSTEM", "All logs cleared", new Timestamp(new Date().getTime()).toString());
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }
    
    // Method to get filtered history for a specific user
    public ArrayList<History> getHistoryForUser(String username) {
        // Validate input
        if (!InputValidator.isValidUsername(username)) {
            return new ArrayList<>();
        }
        
        String sql = "SELECT id, username, name, stock, timestamp FROM history WHERE username = ?";
        ArrayList<History> histories = new ArrayList<History>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                histories.add(new History(rs.getInt("id"),
                               rs.getString("username"),
                               rs.getString("name"),
                               rs.getInt("stock"),
                               rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return histories;
    }
    
    // Method to search history by username or product name
    public ArrayList<History> searchHistory(String searchTerm) {
        if (searchTerm == null || searchTerm.trim().isEmpty()) {
            return getHistory();
        }
        
        // Sanitize input
        searchTerm = InputValidator.sanitizeSQLParam(searchTerm);
        
        String sql = "SELECT id, username, name, stock, timestamp FROM history " +
                     "WHERE username LIKE ? OR name LIKE ?";
        ArrayList<History> histories = new ArrayList<History>();
        
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            
            pstmt.setString(1, "%" + searchTerm + "%");
            pstmt.setString(2, "%" + searchTerm + "%");
            ResultSet rs = pstmt.executeQuery();
            
            while (rs.next()) {
                histories.add(new History(rs.getInt("id"),
                               rs.getString("username"),
                               rs.getString("name"),
                               rs.getInt("stock"),
                               rs.getString("timestamp")));
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return histories;
    }
    
    public Product getProduct(String name){
        String sql = "SELECT name, stock, price FROM product WHERE name='" + name + "';";
        Product product = null;
        try (Connection conn = DriverManager.getConnection(driverURL);
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery(sql)){
            product = new Product(rs.getString("name"),
                                   rs.getInt("stock"),
                                   rs.getFloat("price"));
        } catch (Exception ex) {
            System.out.print(ex);
        }
        return product;
    }
    
     public boolean authenticateUser(String username, String password) {
        if (isAccountLocked(username)) {
            System.out.println("🚫 Account is locked: " + username);
            return false;
        }

        String sql = "SELECT password, salt FROM users WHERE username = ? AND locked = 0";
    
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, username);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                String storedPassword = rs.getString("password");
                String salt = rs.getString("salt");
                byte[] saltBytes = Base64.getDecoder().decode(salt);

                String hashedPassword = hashPassword(password, saltBytes);

                if (storedPassword.equals(hashedPassword)) {
                    // Add successful login log
                    addLogs("LOGIN", username, "User login successful", new Timestamp(new Date().getTime()).toString());
                    resetFailedAttempts(username);
                    return true;
                } else {
                    // Add failed login attempt log
                    addLogs("WARNING", username, "Failed login attempt", new Timestamp(new Date().getTime()).toString());
                    incrementFailedAttempts(username);
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return false;
    }

    public void incrementFailedAttempts(String username) {
      String query = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?";

      try (Connection conn = DriverManager.getConnection(driverURL);
           PreparedStatement stmt = conn.prepareStatement(query)) {
          stmt.setString(1, username);
          stmt.executeUpdate();

          // Get current failed attempts
          int failedAttempts = getFailedAttempts(username);

          // If failed attempts reach 5, lock the account
          if (failedAttempts >= 5) {
              lockAccount(username);
          } else if (failedAttempts >= 3) { 
              int delay = (int) Math.pow(2, failedAttempts - 2);
              System.out.println("⚠️ Login delayed for " + delay + " seconds due to multiple failed attempts.");
              Thread.sleep(delay * 1000);
          }
      } catch (SQLException | InterruptedException e) {
          e.printStackTrace();
      }
    }


    private int getFailedAttempts(String username) {
        String query = "SELECT failed_attempts FROM users WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getInt("failed_attempts");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0; 
    }
   
    public boolean isAccountLocked(String username) {
     String query = "SELECT failed_attempts, locked FROM users WHERE username = ?";

     try (Connection conn = DriverManager.getConnection(driverURL);
          PreparedStatement stmt = conn.prepareStatement(query)) {
         stmt.setString(1, username);
         ResultSet rs = stmt.executeQuery();

         if (rs.next()) {
             int failedAttempts = rs.getInt("failed_attempts");
             int locked = rs.getInt("locked");

             if (failedAttempts >= 5) {
                 lockAccount(username);  
                 return true;
             }
             return locked == 1; 
         }
     } catch (SQLException e) {
         e.printStackTrace();
     }
     return false;
    }

    public void lockAccount(String username) {
     String query = "UPDATE users SET locked = 1 WHERE username = ?";

     try (Connection conn = DriverManager.getConnection(driverURL);
          PreparedStatement stmt = conn.prepareStatement(query)) {
         stmt.setString(1, username);
         stmt.executeUpdate();
         System.out.println("🚫 Account locked for user: " + username);
     } catch (SQLException e) {
         e.printStackTrace();
     }
    }


    public void resetFailedAttempts(String username) {
        String query = "UPDATE users SET failed_attempts = 0 WHERE username = ?";
        try (Connection conn = DriverManager.getConnection(driverURL);
             PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, username);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
            
        }  
    }
    
    public void addTestUser() {
     String username = "testuser";
     String password = "password123";  // Plaintext password for testing

     String sql = "INSERT INTO users (username, password, role, failed_attempts, locked) VALUES (?, ?, ?, 0, 0)";

     try (Connection conn = DriverManager.getConnection(driverURL);
          PreparedStatement stmt = conn.prepareStatement(sql)) {
         stmt.setString(1, username);
         stmt.setString(2, password);
         stmt.setInt(3, 2);  // Role 2 = Regular User (change as needed)
         stmt.executeUpdate();
         System.out.println("✅ Test user 'testuser' added successfully!");
     } catch (SQLException e) {
         if (e.getMessage().contains("UNIQUE constraint failed")) {
             System.out.println("⚠️ Test user 'testuser' already exists.");
         } else {
             e.printStackTrace();
         }
     }
    }  
}