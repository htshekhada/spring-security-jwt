package com.hitesh.springsecurityjwt.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static com.hitesh.springsecurityjwt.auth.AppConstant.AUTH_LOGIN_URL;
import static com.hitesh.springsecurityjwt.auth.AppConstant.AUTH_LOGOUT_URL;

/**
 * Web Security configuration.
 * https://stackoverflow.com/questions/46889350/set-custom
 * -login-url-in-spring-security
 * -usernamepasswordauthenticationfilter-jwt/46890422
 * 
 */
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private DBAuthenticationProvider dbAuthenticationProvider;

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth.authenticationProvider(dbAuthenticationProvider);
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers(HttpMethod.OPTIONS)
				.permitAll()
				.anyRequest()
				.authenticated()
				.and()
				.addFilterBefore(
						new AuthenticationFilter(authenticationManager()),
						UsernamePasswordAuthenticationFilter.class)
				.addFilter(new AuthorizationFilter(authenticationManager()))
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS).and()
				.csrf().disable();
	}

	@Override
	public void configure(WebSecurity web) throws Exception {

		// web.ignoring().antMatchers(AUTH_LOGIN_URL, AUTH_LOGOUT_URL);
		// web.ignoring().antMatchers(AUTH_LOGIN_URL+"/**");
	}

	@Bean
	public AuthenticationFilter getJWTAuthenticationFilter() throws Exception {
		final AuthenticationFilter filter = new AuthenticationFilter(
				authenticationManager());
		filter.setFilterProcessesUrl("/api/auth/login");
		return filter;
	}
}
