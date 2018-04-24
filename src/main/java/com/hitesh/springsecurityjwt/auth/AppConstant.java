package com.hitesh.springsecurityjwt.auth;

public class AppConstant {
	public static final String AUTH_LOGIN_URL = "/app/login";
	public static final String AUTH_LOGOUT_URL = "/app/logout";

	public static final String AUTH_HEADER_NAME = "Authorization";
	public static final long JWT_REMEMBER_ME_EXPIRATION_TIME = 72_00_000; // 5
																			// days
	public static final long JWT_LOGIN_EXPIRATION_TIME = 900_000; // 15 minutes
	public static final String JWT_PREFIX = "Bearer ";
	public static final String JWT_AUTHORITIES_KEY = "authority";
	public static final String JWT_SECRET_KEY = "MyJWTSecretKey";
	public static final String ROLE_MANAGER = "MANAGER";
	public static final String ROLE_ADMIN = "ADMIN";
	public static final String ROLE_USER = "USER";
	public static final String ROLE_DEFAULT = "DEFAULT";

}
