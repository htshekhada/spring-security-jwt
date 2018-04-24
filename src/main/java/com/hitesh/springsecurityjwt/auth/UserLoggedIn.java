package com.hitesh.springsecurityjwt.auth;

import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

public class UserLoggedIn extends User {
	private static final long serialVersionUID = 1L;
	private final String address;
	private boolean rememberMe;

	public UserLoggedIn(String username, String password,
			Collection<GrantedAuthority> authorities, String address) {
		super(username, password, true, true, true, true, authorities);
		this.address = address;
	}

	public String getAddress() {
		return address;
	}

	public boolean isRememberMe() {
		return rememberMe;
	}

	public void setRememberMe(boolean rememberMe) {
		this.rememberMe = rememberMe;
	}
}