package com.campaign.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {

	@GetMapping("/home")
	public ResponseEntity<String> getMessage(){
		return new ResponseEntity<String>("Welcome to home page", HttpStatus.OK);
	}
	
	@GetMapping("/")
	public ResponseEntity<String> HomePage(){
		return new ResponseEntity<String>("Home page", HttpStatus.OK);
	}
	
}
