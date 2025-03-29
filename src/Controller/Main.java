package Controller;

import Model.History;
import Model.Logs;
import Model.Product;
import Model.User;
import View.Frame;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;

import Controller.SessionManager;
import Controller.AuthorizationManager;
import Controller.UserContext;
import Controller.InputValidator;

public class Main {
    
    public SQLite sqlite;
    private SessionManager sessionManager;
    private AuthorizationManager authManager;
    private UserContext userContext;
    
    public static void main(String[] args) {
        new Main().init();
    }
    
    public void init(){
        // Initialize managers
        sessionManager = SessionManager.getInstance();
        authManager = AuthorizationManager.getInstance();
        userContext = UserContext.getInstance();
        
        // Initialize a driver object
        sqlite = new SQLite();

//        // Create a database
//        sqlite.createNewDatabase();
//        
//        // Drop users table if needed
//        sqlite.dropHistoryTable();
//        sqlite.dropLogsTable();
//        sqlite.dropProductTable();
//        sqlite.dropUserTable();
//        
//        // Create users table if not exist
          sqlite.createHistoryTable();
          sqlite.createLogsTable();
          sqlite.createProductTable();
          sqlite.createUserTable();
          sqlite.enableWALMode();
          sqlite.addTestUser(); 
//        
//        // Add sample history
//        sqlite.addHistory("admin", "Antivirus", 1, "2019-04-03 14:30:00.000");
//        sqlite.addHistory("manager", "Firewall", 1, "2019-04-03 14:30:01.000");
//        sqlite.addHistory("staff", "Scanner", 1, "2019-04-03 14:30:02.000");
//        
//        // Add sample logs
//        sqlite.addLogs("NOTICE", "admin", "User creation successful", new Timestamp(new Date().getTime()).toString());
//        sqlite.addLogs("NOTICE", "manager", "User creation successful", new Timestamp(new Date().getTime()).toString());
//        sqlite.addLogs("NOTICE", "admin", "User creation successful", new Timestamp(new Date().getTime()).toString());
//        
//        // Add sample product
//        sqlite.addProduct("Antivirus", 5, 500.0);
//        sqlite.addProduct("Firewall", 3, 1000.0);
//        sqlite.addProduct("Scanner", 10, 100.0);
//
//        // Add sample users
//        sqlite.addUser("admin", "qwerty1234" , 5);
//        sqlite.addUser("manager", "qwerty1234", 4);
//        sqlite.addUser("staff", "qwerty1234", 3);
//        sqlite.addUser("client1", "qwerty1234", 2);
//        sqlite.addUser("client2", "qwerty1234", 2);
//        
//        
//        // Get users
//        ArrayList<History> histories = sqlite.getHistory();
//        for(int nCtr = 0; nCtr < histories.size(); nCtr++){
//            System.out.println("===== History " + histories.get(nCtr).getId() + " =====");
//            System.out.println(" Username: " + histories.get(nCtr).getUsername());
//            System.out.println(" Name: " + histories.get(nCtr).getName());
//            System.out.println(" Stock: " + histories.get(nCtr).getStock());
//            System.out.println(" Timestamp: " + histories.get(nCtr).getTimestamp());
//        }
//        
//        // Get users
//        ArrayList<Logs> logs = sqlite.getLogs();
//        for(int nCtr = 0; nCtr < logs.size(); nCtr++){
//            System.out.println("===== Logs " + logs.get(nCtr).getId() + " =====");
//            System.out.println(" Username: " + logs.get(nCtr).getEvent());
//            System.out.println(" Password: " + logs.get(nCtr).getUsername());
//            System.out.println(" Role: " + logs.get(nCtr).getDesc());
//            System.out.println(" Timestamp: " + logs.get(nCtr).getTimestamp());
//        }
//        
//        // Get users
//        ArrayList<Product> products = sqlite.getProduct();
//        for(int nCtr = 0; nCtr < products.size(); nCtr++){
//            System.out.println("===== Product " + products.get(nCtr).getId() + " =====");
//            System.out.println(" Name: " + products.get(nCtr).getName());
//            System.out.println(" Stock: " + products.get(nCtr).getStock());
//            System.out.println(" Price: " + products.get(nCtr).getPrice());
//        }
//        // Get users
//        ArrayList<User> users = sqlite.getUsers();
//        for(int nCtr = 0; nCtr < users.size(); nCtr++){
//            System.out.println("===== User " + users.get(nCtr).getId() + " =====");
//            System.out.println(" Username: " + users.get(nCtr).getUsername());
//            System.out.println(" Password: " + users.get(nCtr).getPassword());
//            System.out.println(" Role: " + users.get(nCtr).getRole());
//            System.out.println(" Locked: " + users.get(nCtr).getLocked());
//        }
        
        // Initialize User Interface
        Frame frame = new Frame();
        frame.init(this);
    }
    
    // Log user login
    public void logLogin(String username, boolean success) {
        String event = success ? "LOGIN" : "WARNING";
        String desc = success ? "User login successful" : "Failed login attempt";
        sqlite.addLogs(event, username, desc, new Timestamp(new Date().getTime()).toString());
    }
    
    // Log user activity
    public void logActivity(String event, String desc) {
        User currentUser = userContext.getCurrentUser();
        if (currentUser != null) {
            sqlite.addLogs(event, currentUser.getUsername(), desc, new Timestamp(new Date().getTime()).toString());
        } else {
            sqlite.addLogs(event, "ANONYMOUS", desc, new Timestamp(new Date().getTime()).toString());
        }
    }
    
    // Authenticate user and create session
    public boolean authenticate(String username, String password) {
        if (username == null || password == null || username.trim().isEmpty() || password.trim().isEmpty()) {
            return false;
        }
        
        // Validate input
        if (!InputValidator.isValidUsername(username)) {
            logActivity("WARNING", "Invalid username format attempted: " + username);
            return false;
        }
        
        // Authenticate using the SQLite class
        boolean authenticated = sqlite.authenticateUser(username, password);
        
        if (authenticated) {
            // Get user details
            ArrayList<User> users = sqlite.getUsers();
            User authenticatedUser = null;
            
            for (User user : users) {
                if (username.equals(user.getUsername())) {
                    authenticatedUser = user;
                    break;
                }
            }
            
            if (authenticatedUser != null) {
                // Set the current user context
                userContext.setCurrentUser(authenticatedUser);
                logLogin(username, true);
            } else {
                authenticated = false;
            }
        } else {
            logLogin(username, false);
        }
        
        return authenticated;
    }
    
    // Log out the current user
    public void logout() {
        User currentUser = userContext.getCurrentUser();
        if (currentUser != null) {
            logActivity("LOGOUT", "User logout");
        }
        
        userContext.clearContext();
    }
    
    // Get the current user
    public User getCurrentUser() {
        return userContext.getCurrentUser();
    }
    
    // Check if the current user is authorized for an action
    public boolean isAuthorized(String action) {
        return userContext.isAuthorized(action);
    }
    
    // Get home panel for the current user
    public String getHomePanel() {
        User currentUser = userContext.getCurrentUser();
        return authManager.getHomePanel(currentUser);
    }
    
    // Get filtered history for the current user (if client)
    public ArrayList<History> getFilteredHistory() {
        User currentUser = userContext.getCurrentUser();
        if (currentUser == null) {
            return new ArrayList<>();
        }
        
        // If not a client, return all history
        if (currentUser.getRole() > AuthorizationManager.ROLE_CLIENT) {
            return sqlite.getHistory();
        }
        
        // For clients, filter to only show their own history
        ArrayList<History> allHistory = sqlite.getHistory();
        ArrayList<History> filteredHistory = new ArrayList<>();
        
        for (History item : allHistory) {
            if (item.getUsername().equals(currentUser.getUsername())) {
                filteredHistory.add(item);
            }
        }
        
        return filteredHistory;
    }
}