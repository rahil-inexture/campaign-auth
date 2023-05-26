package com.campaign.controller;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.campaign.entity.User;
import com.campaign.repository.UserRepository;

@RestController
public class UserController {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordEncoder passwordEncoder; 
	
	@PostMapping("/users")
	public ResponseEntity<User> createUser(@RequestBody User user){
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		user.setUuid(UUID.randomUUID().toString());
		userRepository.save(user);
		return new ResponseEntity<>(user, HttpStatus.CREATED);
	}
}
