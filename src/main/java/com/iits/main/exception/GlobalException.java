package com.iits.main.exception;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@ControllerAdvice
public class GlobalException {

	@ExceptionHandler(ResourceNotFoundException.class)
	public ResponseEntity<Object> handleResourceNotFoundException(ResourceNotFoundException rne) {
		Map<String, Object> map = new HashMap<>();
		map.put("error", "RESOURCE NOT FOUND");
		map.put("message", rne.getMessage());
		map.put("status", "500");
		return new ResponseEntity<>(map, HttpStatus.INTERNAL_SERVER_ERROR);

	}
	
	@ExceptionHandler(NoResourceFoundException.class)
	public ResponseEntity<Object> handleNoResourceFoundException(NoResourceFoundException nrfe){
		Map<String, Object> map = new HashMap<>();
		map.put("error", "RESOURCE NOT FOUND");
		map.put("message", nrfe.getMessage());
		map.put("status", "404");
		return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
	}
	
	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public ResponseEntity<Object> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException nrfe){
		Map<String, Object> map = new HashMap<>();
		map.put("error", "Method Not Allowed");
		map.put("message", nrfe.getMessage());
		map.put("status", "405");
		return new ResponseEntity<>(map, HttpStatus.METHOD_NOT_ALLOWED);
	}
}
