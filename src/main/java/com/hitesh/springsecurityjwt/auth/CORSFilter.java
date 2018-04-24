package com.hitesh.springsecurityjwt.auth;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

/**
 * CORS filter when Javascript client sends request from different domain.
 * 
 * @author hitesh
 *
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CORSFilter implements Filter {

	private static final Logger logger = LoggerFactory
			.getLogger(CORSFilter.class);

	@Override
	public void init(FilterConfig arg0) throws ServletException {
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res,
			FilterChain chain) throws IOException, ServletException {

		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) res;

		// TODO: Review CORS headers config

		String origin = request.getHeader("Origin");
		if (origin == null)
			origin = "*";
		// Specifies URL which are allowed to access this resource
		response.setHeader("Access-Control-Allow-Origin", origin);
		// Allows submission of credentials and cookies
		response.setHeader("Access-Control-Allow-Credentials", "true");
		// Allowed methods
		response.setHeader("Access-Control-Allow-Methods",
				"POST, GET, PUT, DELETE, OPTIONS");
		// Indicates how long preflight requests can be cached
		response.setHeader("Access-Control-Max-Age", "86400");
		// Used in response to a preflight request to indicate which HTTP
		// headers to be used when making actual request
		response.setHeader("Access-Control-Allow-Headers",
				"Origin, Authorization, Content-Type, X-Requested-With, X-Forwarded-For");
		// Indicates which headers can be exposed as part of the response
		response.setHeader("Access-Control-Expose-Headers",
				"Origin, Authorization, Content-Type, X-Requested-With, X-Forwarded-For");

		if (request.getMethod().equalsIgnoreCase("OPTIONS")) {
			if (logger.isTraceEnabled()) {
				origin = request.getHeader("Origin");
				logger.trace(
						"CORS Pre-Flight Request => Origin : [{}], Remote Addr: [{}], Http Method [{}], Content-Type: [{}]",
						request.getHeader("Origin"), request.getRemoteAddr(),
						request.getMethod(), request.getContentType());

			}
			response.setStatus(HttpServletResponse.SC_OK);
			// Don't go into the chain for OPTIONS
			return;
		}

		chain.doFilter(req, res);

	}

	@Override
	public void destroy() {
	}
}
