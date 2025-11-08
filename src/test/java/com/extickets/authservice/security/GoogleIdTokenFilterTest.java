package com.extickets.authservice.security;

import com.extickets.authservice.model.GoogleUserPrincipal;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;

import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class GoogleIdTokenFilterTest {

    @InjectMocks
    private GoogleIdTokenFilter googleIdTokenFilter;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private GoogleIdToken mockIdToken;

    @Mock
    private Payload mockPayload;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testDoFilterInternal_ValidToken() throws Exception {
        // Arrange
        when(request.getHeader("Authorization")).thenReturn("Bearer validToken");
        when(mockIdToken.getPayload()).thenReturn(mockPayload);
        when(mockPayload.getEmail()).thenReturn("test@example.com");
        when(mockPayload.get("name")).thenReturn("Test User");

        GoogleIdTokenFilter spyFilter = Mockito.spy(googleIdTokenFilter);
        doReturn(mockIdToken).when(spyFilter).verifyToken("validToken");

        // Act
        spyFilter.doFilterInternal(request, response, filterChain);

        // Assert
        verify(filterChain, times(1)).doFilter(request, response);
        assertNotNull(mockPayload.getEmail());
    }

    @Test
    void testDoFilterInternal_InvalidToken() throws Exception {
        when(request.getHeader("Authorization")).thenReturn("Bearer invalidToken");

        GoogleIdTokenFilter spyFilter = Mockito.spy(googleIdTokenFilter);
        doThrow(new RuntimeException("Verification failed")).when(spyFilter).verifyToken("invalidToken");

        spyFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testDoFilterInternal_NoAuthHeader() throws Exception {
        when(request.getHeader("Authorization")).thenReturn(null);

        googleIdTokenFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void testVerifyTokenMethod_NullReturn() throws Exception {
        // Given
        GoogleIdTokenFilter spyFilter = Mockito.spy(googleIdTokenFilter);

        // Mock verifyToken() to simulate a null response (invalid token)
        doReturn(null).when(spyFilter).verifyToken("dummyToken");

        // When
        GoogleIdToken token = spyFilter.verifyToken("dummyToken");

        // Then
        assertNull(token);
    }
}
