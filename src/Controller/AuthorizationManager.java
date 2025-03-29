package Controller;

import Model.User;

public class AuthorizationManager {
    
    // Role constants
    public static final int ROLE_DISABLED = 1;
    public static final int ROLE_CLIENT = 2;
    public static final int ROLE_STAFF = 3;
    public static final int ROLE_MANAGER = 4;
    public static final int ROLE_ADMIN = 5;
    
    private static AuthorizationManager instance;
    
    // Private constructor for Singleton pattern
    private AuthorizationManager() {
    }
    
    // Get singleton instance
    public static synchronized AuthorizationManager getInstance() {
        if (instance == null) {
            instance = new AuthorizationManager();
        }
        return instance;
    }
    
    // Check if a user can perform an action based on their role
    public boolean isAuthorized(User user, String action) {
        if (user == null) {
            return false;
        }
        
        // If account is locked, no permissions are granted
        if (user.getLocked() == 1) {
            return false;
        }
        
        int role = user.getRole();
        
        switch (action) {
            // Client permissions (view products, purchase, view own history)
            case "VIEW_PRODUCTS":
            case "PURCHASE_PRODUCTS":
            case "VIEW_OWN_HISTORY":
                return role >= ROLE_CLIENT;
                
            // Staff permissions (view users, view all history, view logs)
            case "VIEW_USERS":
            case "VIEW_ALL_HISTORY":
            case "VIEW_LOGS":
                return role >= ROLE_STAFF;
                
            // Manager permissions (edit products, add products)
            case "EDIT_PRODUCTS":
            case "ADD_PRODUCTS":
                return role >= ROLE_MANAGER;
                
            // Admin permissions (edit roles, delete users, lock/unlock users)
            case "EDIT_ROLES":
            case "DELETE_USERS":
            case "LOCK_UNLOCK_USERS":
            case "CHANGE_USER_PASSWORD":
                return role >= ROLE_ADMIN;
                
            default:
                return false;
        }
    }
    
    // Get a readable name for a role ID
    public String getRoleName(int roleId) {
        switch (roleId) {
            case ROLE_DISABLED:
                return "Disabled";
            case ROLE_CLIENT:
                return "Client";
            case ROLE_STAFF:
                return "Staff";
            case ROLE_MANAGER:
                return "Manager";
            case ROLE_ADMIN:
                return "Admin";
            default:
                return "Unknown";
        }
    }
    
    // Check if a user is allowed to access a specific panel
    public boolean canAccessPanel(User user, String panelName) {
        if (user == null || user.getLocked() == 1) {
            return false;
        }
        
        int role = user.getRole();
        
        switch (panelName) {
            case "clientHomePnl":
                return role >= ROLE_CLIENT;
            case "staffHomePnl":
                return role >= ROLE_STAFF;
            case "managerHomePnl":
                return role >= ROLE_MANAGER;
            case "adminHomePnl":
                return role >= ROLE_ADMIN;
            default:
                return false;
        }
    }
    
    // Determine which home panel to show based on user role
    public String getHomePanel(User user) {
        if (user == null || user.getLocked() == 1) {
            return "loginPnl";
        }
        
        int role = user.getRole();
        
        if (role >= ROLE_ADMIN) {
            return "adminHomePnl";
        } else if (role >= ROLE_MANAGER) {
            return "managerHomePnl";
        } else if (role >= ROLE_STAFF) {
            return "staffHomePnl";
        } else if (role >= ROLE_CLIENT) {
            return "clientHomePnl";
        } else {
            return "loginPnl";
        }
    }
}