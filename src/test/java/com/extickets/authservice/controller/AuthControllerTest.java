package com.extickets.authservice.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;

import com.extickets.authservice.security.JwtUtil;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;

public class AuthControllerTest {
	private AuthController controller;
    private JwtUtil jwtUtil;

    @BeforeEach
    void setup() {
        jwtUtil = mock(JwtUtil.class);
        controller = new AuthController();

        // Inject JwtUtil into controller using reflection
        try {
            var field = AuthController.class.getDeclaredField("jwtUtil");
            field.setAccessible(true);
            field.set(controller, jwtUtil);
        } catch (Exception ignored) {}
    }

    @Test
    void testGoogleAuth_ValidToken() throws Exception {
        GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
        GoogleIdToken token = mock(GoogleIdToken.class);
        Payload payload = new Payload();
        payload.setEmail("user@gmail.com");
        payload.put("name", "Test User");

        when(verifier.verify(anyString())).thenReturn(token);
        when(token.getPayload()).thenReturn(payload);
        when(jwtUtil.generateToken("user@gmail.com", "Test User")).thenReturn("mock-jwt");

        // ✅ Use MockedConstruction instead of MockedStatic for new object
        try (MockedConstruction<GoogleIdTokenVerifier.Builder> mocked = Mockito.mockConstruction(
                GoogleIdTokenVerifier.Builder.class,
                (builder, context) -> {
                    when(builder.setAudience(anyList())).thenReturn(builder);
                    when(builder.build()).thenReturn(verifier);
                })) {

            ResponseEntity<?> response = controller.googleAuth(Map.of("idToken", "dummy-token"));
            assertEquals(200, response.getStatusCodeValue());
            assertTrue(response.getBody().toString().contains("mock-jwt"));
        }
    }

    @Test
    void testGoogleAuth_InvalidToken() throws Exception {
        GoogleIdTokenVerifier verifier = mock(GoogleIdTokenVerifier.class);
        when(verifier.verify(anyString())).thenReturn(null);

        try (MockedConstruction<GoogleIdTokenVerifier.Builder> mocked = Mockito.mockConstruction(
                GoogleIdTokenVerifier.Builder.class,
                (builder, context) -> {
                    when(builder.setAudience(anyList())).thenReturn(builder);
                    when(builder.build()).thenReturn(verifier);
                })) {

            ResponseEntity<?> response = controller.googleAuth(Map.of("idToken", "invalid-token"));
            assertEquals(401, response.getStatusCodeValue());
        }
    }

    @Test
    void testGoogleAuth_Exception() throws Exception {
        // Simulate failure in Builder
        try (MockedConstruction<GoogleIdTokenVerifier.Builder> mocked = Mockito.mockConstruction(
                GoogleIdTokenVerifier.Builder.class,
                (builder, context) -> when(builder.build()).thenThrow(new RuntimeException("test error")))) {

            ResponseEntity<?> response = controller.googleAuth(Map.of("idToken", "error"));
            assertEquals(500, response.getStatusCodeValue());
        }
    }
}
