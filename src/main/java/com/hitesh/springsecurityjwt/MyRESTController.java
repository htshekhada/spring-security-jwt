package com.hitesh.springsecurityjwt;

import java.util.Collections;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/my-rest/")
public class MyRESTController {

	@RequestMapping(value = "all-role-access", method = RequestMethod.GET)
	public ResponseEntity<Map<String, String>> allAuthorized() {
		Map<String, String> map = Collections.singletonMap("response",
				"Hello World");
		HttpHeaders headers = new HttpHeaders();
		headers.add("custom-header", "cust-head-value");
		HttpStatus httpStatus = HttpStatus.OK;
		ResponseEntity<Map<String, String>> responseEntity = new ResponseEntity<Map<String, String>>(
				map, headers, httpStatus);
		return responseEntity;
	}

	@PreAuthorize("hasAuthority('MANAGER')")
	@RequestMapping(value = "manager-access", method = RequestMethod.GET)
	public ResponseEntity<String> managerAuthorized() {
		String body = "Manager can access this.";
		HttpStatus httpStatus = HttpStatus.OK;
		ResponseEntity<String> responseEntity = new ResponseEntity<String>(
				body, httpStatus);
		return responseEntity;
	}

	@PreAuthorize("hasAuthority('ADMIN')")
	@RequestMapping(value = "admin-access", method = RequestMethod.GET)
	public ResponseEntity<String> adminAuthorized() {
		return new ResponseEntity<String>("Only admin can access this.",
				HttpStatus.OK);
	}

	@PreAuthorize("hasAuthority('ADMIN','MANAGER')")
	@RequestMapping(value = "admin-manager-access", method = RequestMethod.GET)
	public ResponseEntity<String> adminMgrAuthorized() {
		return new ResponseEntity<String>("Admin and Manager can access this.",
				HttpStatus.OK);
	}

}
