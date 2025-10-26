package com.extickets.authservice.controller;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.extickets.authservice.security.JwtUtil;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = { "http://localhost:3000", "http://192.168.29.94:3000" }, allowCredentials = "true")
public class AuthController {

	private static final String GOOGLE_CLIENT_ID = "464546863135-1991ht6skloqe2dapfj53k61k2cmj0h3.apps.googleusercontent.com";

	@Autowired
	private JwtUtil jwtUtil;

	@PostMapping("/google")
	public ResponseEntity<?> googleAuth(@RequestBody Map<String, String> body) {
		String token = body.get("idToken");
		try {
			GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(),
					JacksonFactory.getDefaultInstance()).setAudience(Collections.singletonList(GOOGLE_CLIENT_ID))
					.build();

			GoogleIdToken idToken = verifier.verify(token);
			if (idToken != null) {
				GoogleIdToken.Payload payload = idToken.getPayload();

				String email = payload.getEmail();
				String name = (String) payload.get("name");

				// Generate your internal JWT
				String jwtToken = jwtUtil.generateToken(email, name);
				System.out.println("JWT Token : " + jwtToken);
				// For Spring context
				User springUser = new User(email, "", List.of());
				UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(springUser,
						null, springUser.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);

				return ResponseEntity.ok(Map.of( "token", jwtToken));
			} else {
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid ID token.");
			}
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Token verification failed");
		}
	}
}
