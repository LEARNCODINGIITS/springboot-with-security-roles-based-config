package com.iits.main.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v/")
public class MyController {

	
	@GetMapping("msg")
	@PreAuthorize("hasRole('ADMIN')")
	//@Secured("USER")
	public String message(Authentication authentication) {
		System.out.println(authentication.getCredentials());
		System.out.println(authentication.getDetails());
		System.out.println(authentication.getName());
		System.out.println(authentication.getPrincipal());
		return "Hello From ADMIN";
	}
	@GetMapping("msg1")
	@PreAuthorize("hasRole('USER')")
	//@Secured("USER")
	public String message1(Authentication authentication) {
		System.out.println(authentication.getCredentials());
		System.out.println(authentication.getDetails());
		System.out.println(authentication.getName());
		System.out.println(authentication.getPrincipal());
		return "Hello From USER";
	}
}
