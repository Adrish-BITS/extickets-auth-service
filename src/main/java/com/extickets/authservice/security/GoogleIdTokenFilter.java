package com.extickets.authservice.security;

import java.io.IOException;
import java.util.Collections;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.extickets.authservice.model.GoogleUserPrincipal;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class GoogleIdTokenFilter extends OncePerRequestFilter {

	private static final String CLIENT_ID = "464546863135-1991ht6skloqe2dapfj53k61k2cmj0h3.apps.googleusercontent.com";

	private final GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(),
			JacksonFactory.getDefaultInstance()).setAudience(Collections.singletonList(CLIENT_ID)).build();

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String authHeader = request.getHeader("Authorization");
		if (authHeader != null && authHeader.startsWith("Bearer ")) {
			String idTokenString = authHeader.substring(7);
			try {
				GoogleIdToken idToken = verifier.verify(idTokenString);
				GoogleIdToken.Payload payload = idToken.getPayload();
			    String email = payload.getEmail();
			    String name = (String) payload.get("name");

			    // Create your principal object
			    GoogleUserPrincipal principal = new GoogleUserPrincipal(email, name);

			    UsernamePasswordAuthenticationToken authentication =
			        new UsernamePasswordAuthenticationToken(principal, null, Collections.emptyList());

			    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

			    SecurityContextHolder.getContext().setAuthentication(authentication);
			} catch (Exception e) {
				System.out.println("Invalid ID token: " + e.getMessage());
			}
		}

		filterChain.doFilter(request, response);
	}
	protected GoogleIdToken verifyToken(String token) throws Exception {
	    return verifier.verify(token);
	}
}
