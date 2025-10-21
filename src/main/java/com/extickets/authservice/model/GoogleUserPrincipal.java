package com.extickets.authservice.model;

public class GoogleUserPrincipal {
	private final String email;
    private final String name;

    public GoogleUserPrincipal(String email, String name) {
        this.email = email;
        this.name = name;
    }

    public String getEmail() { return email; }
    public String getName() { return name; }
}
