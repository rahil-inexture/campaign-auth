package com.campaign.security;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.campaign.entity.User;
import com.campaign.repository.UserRepository;

@Component
public class UserDetailsServiceImpl implements UserDetailsService{
	
	@Autowired
	private UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Optional<User> userOptional = userRepository.findByEmail(username);
		if(!userOptional.isPresent()) {
			throw new RuntimeException("user not found with username : "+username);
		}
		User user = userOptional.get();
		CustomUserDetails userDetails = new CustomUserDetails(user);
		return userDetails;
	}

}
