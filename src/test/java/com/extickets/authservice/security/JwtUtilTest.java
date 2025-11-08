package com.extickets.authservice.security;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilTest {

    private JwtUtil jwtUtil;
    private String testEmail;
    private String testName;

    @BeforeEach
    void setUp() {
        jwtUtil = new JwtUtil();
        testEmail = "testuser@example.com";
        testName = "Test User";
    }

    @Test
    void testGenerateToken_ShouldContainCorrectClaims() {
        String token = jwtUtil.generateToken(testEmail, testName);
        assertNotNull(token);
        assertTrue(token.length() > 20);

        // Extract email from token
        String extractedEmail = jwtUtil.validateAndExtractEmail(token);
        assertEquals(testEmail, extractedEmail);
    }

    @Test
    void testValidateAndExtractEmail_ShouldReturnCorrectSubject() {
        String token = jwtUtil.generateToken(testEmail, testName);
        String email = jwtUtil.validateAndExtractEmail(token);
        assertEquals(testEmail, email);
    }

    @Test
    void testValidateAndExtractEmail_ShouldThrowForExpiredToken() {
        // Create an expired token manually
        SecretKey key = (SecretKey) getPrivateField(jwtUtil, "key");
        String expiredToken = Jwts.builder()
                .setSubject(testEmail)
                .setExpiration(new Date(System.currentTimeMillis() - 1000)) // already expired
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        assertThrows(ExpiredJwtException.class, () -> jwtUtil.validateAndExtractEmail(expiredToken));
    }

    // Utility method to access private fields (since key is private and final)
    private Object getPrivateField(Object obj, String fieldName) {
        try {
            var field = obj.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            return field.get(obj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
