package com.campaign.controller;

import java.util.Date;
import java.util.Optional;

import org.apache.kafka.common.Uuid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.campaign.dto.UserDto;
import com.campaign.entity.User;
import com.campaign.entity.UserAuth;
import com.campaign.repository.UserAuthRepository;
import com.campaign.repository.UserRepository;
import com.campaign.security.JwtTokenService;

@RestController
@RequestMapping("/auth")
public class AuthController {
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private UserAuthRepository userAuthRepository;
	
	@Autowired
	private JwtTokenService jwtTokenService;
	
	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@PostMapping("/authenticate")
	public ResponseEntity<String> authenticate(@RequestBody UserDto userDto){
		Optional<User> optionalUser = userRepository.findByEmail(userDto.getEmail());
		
		if(optionalUser.isPresent()) {
			User userEntity = optionalUser.get();
			boolean valid = passwordEncoder.matches(userDto.getPassword(), userEntity.getPassword());
			if(valid) {
				String jwtToken = jwtTokenService.generateToken(userEntity);
				
				Date  expiresAt = jwtTokenService.extractExpiration(jwtToken);
				Date issuedAt = jwtTokenService.extractIssuedAt(jwtToken);
				
				UserAuth userAuth = new UserAuth();
		    	userAuth.setUserId(userEntity.getUserId());
		        userAuth.setAccessToken(jwtToken);
		        userAuth.setExpiresAt(expiresAt);
		        userAuth.setIssuedAt(issuedAt);
		        userAuth.setUuid(Uuid.randomUuid().toString());
		    	userAuthRepository.save(userAuth);
		    	
				return new ResponseEntity<>(jwtToken, HttpStatus.CREATED);
			}
		}    	
		return new ResponseEntity<>("Invalid Credential", HttpStatus.OK);
	}

}
