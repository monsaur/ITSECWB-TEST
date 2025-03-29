package Controller;

import Model.User;

public class UserContext {
    
    private static UserContext instance;
    private User currentUser;
    private String sessionId;
    
    // Private constructor for Singleton pattern
    private UserContext() {
        this.currentUser = null;
        this.sessionId = null;
    }
    
    // Get singleton instance
    public static synchronized UserContext getInstance() {
        if (instance == null) {
            instance = new UserContext();
        }
        return instance;
    }
    
    // Set the current user and create a session
    public void setCurrentUser(User user) {
        this.currentUser = user;
        
        if (user != null) {
            this.sessionId = SessionManager.getInstance().createSession(user);
        } else {
            this.sessionId = null;
        }
    }
    
    // Get the current user
    public User getCurrentUser() {
        // Verify session is still valid
        if (sessionId != null && !SessionManager.getInstance().isSessionValid(sessionId)) {
            // Session expired, clear user context
            clearContext();
            return null;
        }
        
        return currentUser;
    }
    
    // Get the current user's session ID
    public String getSessionId() {
        return sessionId;
    }
    
    // Check if a user is logged in
    public boolean isLoggedIn() {
        return getCurrentUser() != null && sessionId != null;
    }
    
    // Clear the current user context (logout)
    public void clearContext() {
        if (sessionId != null) {
            SessionManager.getInstance().invalidateSession(sessionId);
        }
        
        this.currentUser = null;
        this.sessionId = null;
    }
    
    // Check if current user is authorized for an action
    public boolean isAuthorized(String action) {
        User user = getCurrentUser();
        if (user == null) {
            return false;
        }
        
        return AuthorizationManager.getInstance().isAuthorized(user, action);
    }
    
    // Get the current user's role
    public int getCurrentUserRole() {
        User user = getCurrentUser();
        if (user == null) {
            return 0;
        }
        
        return user.getRole();
    }
}