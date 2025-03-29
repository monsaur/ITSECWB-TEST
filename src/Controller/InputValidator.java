package Controller;

import java.util.regex.Pattern;

public class InputValidator {
    
    // Username pattern: alphanumeric, min 3 chars, max 20 chars
    private static final Pattern USERNAME_PATTERN = 
        Pattern.compile("^[a-zA-Z0-9_]{3,20}$");
    
    // Password pattern: at least 8 chars, must include uppercase, lowercase, and digit
    private static final Pattern PASSWORD_PATTERN = 
        Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z]).{8,64}$");
    
    // Product name pattern: alphanumeric with spaces, min 2 chars, max 50 chars
    private static final Pattern PRODUCT_NAME_PATTERN = 
        Pattern.compile("^[a-zA-Z0-9 ]{2,50}$");
    
    // Numeric pattern: digits only
    private static final Pattern NUMERIC_PATTERN = 
        Pattern.compile("^[0-9]+$");
    
    // Price pattern: digits with optional decimal point and up to 2 decimal places
    private static final Pattern PRICE_PATTERN = 
        Pattern.compile("^[0-9]+(\\.[0-9]{1,2})?$");
    
    // Validate username
    public static boolean isValidUsername(String username) {
        if (username == null) {
            return false;
        }
        return USERNAME_PATTERN.matcher(username).matches();
    }
    
    // Validate password
    public static boolean isValidPassword(String password) {
        if (password == null) {
            return false;
        }
        return PASSWORD_PATTERN.matcher(password).matches();
    }
    
    // Validate product name
    public static boolean isValidProductName(String name) {
        if (name == null) {
            return false;
        }
        return PRODUCT_NAME_PATTERN.matcher(name).matches();
    }
    
    // Validate numeric input (for stock)
    public static boolean isValidNumeric(String number) {
        if (number == null) {
            return false;
        }
        return NUMERIC_PATTERN.matcher(number).matches();
    }
    
    // Validate price input
    public static boolean isValidPrice(String price) {
        if (price == null) {
            return false;
        }
        return PRICE_PATTERN.matcher(price).matches();
    }
    
    // Sanitize input to prevent XSS
    public static String sanitizeInput(String input) {
        if (input == null) {
            return null;
        }
        
        // Replace potentially dangerous characters
        return input.replaceAll("<", "&lt;")
                   .replaceAll(">", "&gt;")
                   .replaceAll("\"", "&quot;")
                   .replaceAll("'", "&#x27;")
                   .replaceAll("/", "&#x2F;");
    }
    
    // Validate SQL parameters to prevent injection
    public static String sanitizeSQLParam(String param) {
        if (param == null) {
            return null;
        }
        
        // Remove SQL injection characters
        return param.replaceAll("'", "''") // Escape single quotes
                   .replaceAll(";", "") // Remove semicolons
                   .replaceAll("--", "") // Remove comment indicators
                   .replaceAll("/\\*", "") // Remove comment start
                   .replaceAll("\\*/", ""); // Remove comment end
    }
}