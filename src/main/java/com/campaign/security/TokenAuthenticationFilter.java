package com.campaign.security;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter{
	
	static final Logger log = LoggerFactory.getLogger(TokenAuthenticationFilter.class);
	
	@Autowired
	private AzureTokenService azureTokenService;
	
	@Autowired
	private JwtTokenService jwtTokenService;
	
	@Autowired
	private UserDetailsServiceImpl userDetailsServiceImpl;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		final String authHeader = request.getHeader("Authorization");
		final String token;
		
		if(authHeader!=null && authHeader.startsWith("Bearer ")) {
			token = authHeader.substring(7);
			log.info("token:"+token);
			
			try {
				boolean azureToken = azureTokenService.isAzureToken(token);
				String username;
				boolean tokenValid;
				if(azureToken) {
					username = azureTokenService.extractUsername(token);
					log.info("username:"+username);
					tokenValid = azureTokenService.isTokenValid(token);
				}else {
					username = jwtTokenService.extractUsername(token);
					log.info("username:"+username);
					tokenValid = jwtTokenService.isTokenValid(token);
				}
				UserDetails userDetails = userDetailsServiceImpl.loadUserByUsername(username);
				
				if(tokenValid) {
					log.info("valid:"+true);
					UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
					log.info("authToken:"+authToken);
					SecurityContextHolder.getContext().setAuthentication(authToken);
				}		
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		filterChain.doFilter(request, response);
	}

}