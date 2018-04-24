package com.hitesh.springsecurityjwt.auth;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import static com.hitesh.springsecurityjwt.auth.AppConstant.ROLE_USER;
import static com.hitesh.springsecurityjwt.auth.AppConstant.ROLE_ADMIN;
import static com.hitesh.springsecurityjwt.auth.AppConstant.ROLE_MANAGER;
import static com.hitesh.springsecurityjwt.auth.AppConstant.ROLE_DEFAULT;

/**
 * Validate username/password against database.
 * 
 * @author hiteshs
 *
 */
@Component
public class DBAuthenticationProvider implements AuthenticationProvider {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(DBAuthenticationProvider.class);

	@Override
	public Authentication authenticate(Authentication authentication)
			throws AuthenticationException {

		String username = authentication.getName().trim();
		String password = authentication.getCredentials().toString().trim();
		Authentication auth = null;

		// validate against database
		if ("password".equals(password)) {
			String authority = ROLE_DEFAULT;

			List<GrantedAuthority> grantedAuthority = new ArrayList<GrantedAuthority>();
			grantedAuthority.add(new SimpleGrantedAuthority(authority.trim()));

			UserLoggedIn authenticatedUser = new UserLoggedIn(username,
					password, grantedAuthority, "va, usa");
			auth = new UsernamePasswordAuthenticationToken(authenticatedUser,
					password, grantedAuthority);

			LOGGER.info("Your '{}' Authentication Ok", username);
			return auth;
		} else {
			throw new BadCredentialsException("Wrong Credentials");
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {

		return (UsernamePasswordAuthenticationToken.class
				.isAssignableFrom(authentication));
	}

}
