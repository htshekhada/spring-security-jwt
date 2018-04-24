package com.hitesh.springsecurityjwt.auth;

import static com.hitesh.springsecurityjwt.auth.AppConstant.AUTH_HEADER_NAME;
import static com.hitesh.springsecurityjwt.auth.AppConstant.AUTH_LOGIN_URL;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_AUTHORITIES_KEY;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_LOGIN_EXPIRATION_TIME;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_PREFIX;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_REMEMBER_ME_EXPIRATION_TIME;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_SECRET_KEY;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.hitesh.springsecurityjwt.auth.pojo.LoginUser;

/**
 * Authentication filter.
 * 
 * @author hitesh
 *
 */
public class AuthenticationFilter extends
		AbstractAuthenticationProcessingFilter {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(AuthenticationFilter.class);

	private AuthenticationManager authenticationManager;

	private boolean rememberMe;

	public AuthenticationFilter(AuthenticationManager authenticationManager) {
		// Initiate authentication flow, only if it is POST request for
		// SecurityConstants.AUTH_LOGIN_URL
		super(new AntPathRequestMatcher(AUTH_LOGIN_URL, "POST"));
		this.authenticationManager = authenticationManager;
	}

	// Attempt authentication via AuthenticationManager (as configured in
	// WebSecurityConfig.java)
	@Override
	public Authentication attemptAuthentication(HttpServletRequest req,
			HttpServletResponse res) throws AuthenticationException,
			IOException {

		try {
			// Mapping of request json payload with java DTO
			LoginUser login = new ObjectMapper().readValue(
					req.getInputStream(), LoginUser.class);

			// Do necessary validations
			validateLoginRequestPayload(res, login);

			this.setRememberMe(login.isRememberMe());

			// Authenticate user credentials
			return authenticationManager
					.authenticate(new UsernamePasswordAuthenticationToken(login
							.getUsername(), login.getPassword(),
							new ArrayList<>()));

		} catch (JsonMappingException e) {
			res.sendError(HttpServletResponse.SC_BAD_REQUEST,
					"Invalid json in request body");
		} catch (IOException e) {
			res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
					"Error occured");
			LOGGER.error("Unexpected error occured", e);
		}
		return null;
	}

	// On successful authentication, generate JWT and add it in header
	@Override
	protected void successfulAuthentication(HttpServletRequest req,
			HttpServletResponse res, FilterChain chain, Authentication auth)
			throws IOException, ServletException {

		UserLoggedIn user = (UserLoggedIn) auth.getPrincipal();

		GrantedAuthority role = user.getAuthorities().stream().findFirst()
				.get();

		String token = Jwts
				.builder()
				.setSubject(user.getUsername())
				.claim(JWT_AUTHORITIES_KEY, role.getAuthority())
				.setIssuedAt(new Date())
				.setExpiration(
						new Date(
								System.currentTimeMillis()
										+ (this.isRememberMe() ? JWT_REMEMBER_ME_EXPIRATION_TIME
												: JWT_LOGIN_EXPIRATION_TIME)))
				.signWith(SignatureAlgorithm.HS512, JWT_SECRET_KEY.getBytes())
				.compact();

		res.addHeader(AUTH_HEADER_NAME, JWT_PREFIX + token);
	}

	private void validateLoginRequestPayload(HttpServletResponse res,
			LoginUser login) throws IOException {
		// TODO: Do validations as per functional requirements
		if (login.getUsername() == null)
			res.sendError(HttpServletResponse.SC_BAD_REQUEST,
					"Null username is not allowed");

		if (login.getPassword() == null)
			res.sendError(HttpServletResponse.SC_BAD_REQUEST,
					"Null password is not allowed");
	}

	public boolean isRememberMe() {
		return rememberMe;
	}

	public void setRememberMe(boolean rememberMe) {
		this.rememberMe = rememberMe;
	}
}
