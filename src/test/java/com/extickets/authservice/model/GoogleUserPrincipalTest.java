package com.extickets.authservice.model;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class GoogleUserPrincipalTest {

    @Test
    void testConstructorAndGetters() {
        // Arrange
        String email = "testuser@gmail.com";
        String name = "Test User";

        // Act
        GoogleUserPrincipal principal = new GoogleUserPrincipal(email, name);

        // Assert
        assertEquals(email, principal.getEmail());
        assertEquals(name, principal.getName());
        assertNotNull(principal.getEmail());
        assertNotNull(principal.getName());
    }

    @Test
    void testDifferentValues() {
        GoogleUserPrincipal principal = new GoogleUserPrincipal("another@gmail.com", "Another User");
        assertEquals("another@gmail.com", principal.getEmail());
        assertEquals("Another User", principal.getName());
    }
}
