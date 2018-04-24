package com.hitesh.springsecurityjwt.auth;

import static com.hitesh.springsecurityjwt.auth.AppConstant.AUTH_HEADER_NAME;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_AUTHORITIES_KEY;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_PREFIX;
import static com.hitesh.springsecurityjwt.auth.AppConstant.JWT_SECRET_KEY;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	private static final Logger LOGGER = LoggerFactory
			.getLogger(AuthorizationFilter.class);

	public AuthorizationFilter(AuthenticationManager authManager) {
		super(authManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req,
			HttpServletResponse res, FilterChain chain) throws IOException,
			ServletException {

		String header = req.getHeader(AUTH_HEADER_NAME);

		if (header == null || !header.startsWith(JWT_PREFIX)) {
			res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
					"You are not authorised to access this end point");

			return;
		} else {
			// valid JWT token?
			try {
				String jwt = header.substring(JWT_PREFIX.length());
				Claims claims = Jwts.parser()
						.setSigningKey(JWT_SECRET_KEY.getBytes())
						.parseClaimsJws(jwt.replace(JWT_PREFIX, "")).getBody();

				SecurityContextHolder.getContext().setAuthentication(
						getAuthentication(claims));

			} catch (SignatureException e) {
				res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
						"Invalid token signaturee");
			} catch (ExpiredJwtException e) {
				res.sendError(HttpServletResponse.SC_UNAUTHORIZED,
						"Token has expiered");
			} catch (Exception e) {
				res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
						"Error has occured");
				LOGGER.error("Unexpected errorr", e);
			}

			chain.doFilter(req, res);
		}
	}

	private Authentication getAuthentication(Claims claims) {

		String user = claims.getSubject();
		List<SimpleGrantedAuthority> authorities = new ArrayList<SimpleGrantedAuthority>();
		String authority = (String) claims.get(JWT_AUTHORITIES_KEY);
		authorities.add(new SimpleGrantedAuthority(authority));

		return new UsernamePasswordAuthenticationToken(user, "", authorities);
	}
}
