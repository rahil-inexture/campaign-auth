package com.campaign.security;

import java.text.ParseException;
import java.time.Instant;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.campaign.repository.UserAuthRepository;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.impl.DefaultClaims;

@Service
public class AzureTokenService {
	
	static final Logger log = LoggerFactory.getLogger(AzureTokenService.class);
	
	@Autowired
	UserAuthRepository userAuthRepository;
	
	public String extractUsername(String token) throws ParseException {
		return (String) extractClaim(token, "unique_name");
	}
	
	public Object extractClaim(String token, String claim) throws ParseException {
		final Claims claims = extractAllClaims(token);
		return claims.get(claim, Object.class);
	}
	
	private Claims extractAllClaims(String token) throws ParseException {
		JWT jwt = JWTParser.parse(token);
		Map<String,Object> claims=jwt.getJWTClaimsSet().getClaims();
		Claims jwtClaims = new DefaultClaims(claims);
		return jwtClaims;		
	}
	
	public boolean isTokenValid(String token) throws ParseException {
		boolean existsByAccessToken = userAuthRepository.existsByAccessToken(token);
		return (existsByAccessToken && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) throws ParseException {
		long expiration = extractExpiration(token);
		Instant expirationInstant = Instant.ofEpochSecond(expiration);
		boolean isExpired = expirationInstant.isBefore(Instant.now());
		log.info("isExpired:"+isExpired);
		return isExpired;
	}
	
	public boolean isAzureToken(String token) throws ParseException {
		return (extractClaim(token, "aud")!=null || extractClaim(token, "iss")!=null);
	}

	private long extractExpiration(String token) throws ParseException {
		return (long) extractClaim(token, "exp");
	}

}
