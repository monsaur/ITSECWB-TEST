package Controller;

import Model.User;
import java.util.HashMap;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;

public class SessionManager {
    
    private static SessionManager instance;
    private Map<String, UserSession> activeSessions;
    private final long SESSION_TIMEOUT = 30 * 60 * 1000; // 30 minutes in milliseconds
    private Timer sessionTimer;
    
    // Private constructor for Singleton pattern
    private SessionManager() {
        activeSessions = new HashMap<>();
        sessionTimer = new Timer(true);
        
        // Schedule session cleanup task every 5 minutes
        sessionTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                cleanupExpiredSessions();
            }
        }, 5 * 60 * 1000, 5 * 60 * 1000);
    }
    
    // Get singleton instance
    public static synchronized SessionManager getInstance() {
        if (instance == null) {
            instance = new SessionManager();
        }
        return instance;
    }
    
    // Create a new session for a user
    public String createSession(User user) {
        if (user == null) {
            return null;
        }
        
        // Generate a session ID
        String sessionId = generateSessionId();
        
        // Create and store the session
        UserSession session = new UserSession(user, sessionId);
        activeSessions.put(sessionId, session);
        
        return sessionId;
    }
    
    // Get the user associated with a session
    public User getUserBySessionId(String sessionId) {
        if (sessionId == null || !activeSessions.containsKey(sessionId)) {
            return null;
        }
        
        UserSession session = activeSessions.get(sessionId);
        
        // Check if session is valid
        if (session.isExpired()) {
            activeSessions.remove(sessionId);
            return null;
        }
        
        // Update last activity time
        session.updateLastActivity();
        return session.getUser();
    }
    
    // Invalidate a session (logout)
    public void invalidateSession(String sessionId) {
        if (sessionId != null) {
            activeSessions.remove(sessionId);
        }
    }
    
    // Check if a session is valid
    public boolean isSessionValid(String sessionId) {
        if (sessionId == null || !activeSessions.containsKey(sessionId)) {
            return false;
        }
        
        UserSession session = activeSessions.get(sessionId);
        if (session.isExpired()) {
            activeSessions.remove(sessionId);
            return false;
        }
        
        session.updateLastActivity();
        return true;
    }
    
    // Remove expired sessions
    private void cleanupExpiredSessions() {
        long currentTime = System.currentTimeMillis();
        
        activeSessions.entrySet().removeIf(entry -> 
            (currentTime - entry.getValue().getLastActivity()) > SESSION_TIMEOUT);
    }
    
    // Generate a unique session ID
    private String generateSessionId() {
        return java.util.UUID.randomUUID().toString();
    }
    
    // Inner class to represent a user session
    private class UserSession {
        private User user;
        private String sessionId;
        private long lastActivity;
        
        public UserSession(User user, String sessionId) {
            this.user = user;
            this.sessionId = sessionId;
            this.lastActivity = System.currentTimeMillis();
        }
        
        public User getUser() {
            return user;
        }
        
        public String getSessionId() {
            return sessionId;
        }
        
        public long getLastActivity() {
            return lastActivity;
        }
        
        public void updateLastActivity() {
            this.lastActivity = System.currentTimeMillis();
        }
        
        public boolean isExpired() {
            return (System.currentTimeMillis() - lastActivity) > SESSION_TIMEOUT;
        }
    }
}