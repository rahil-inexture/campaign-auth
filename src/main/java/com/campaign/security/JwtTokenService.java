package com.campaign.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.campaign.entity.User;
import com.campaign.repository.UserAuthRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtTokenService {
	
	@Value("${jwt.secret}")
	private String jwtSecret;

	@Value("${jwt.token.validity}")
	private String tokenValidity;
	
	public long getTokenValidity() {
		return Long.parseLong(tokenValidity);
	}
	
	@Autowired
	UserAuthRepository userAuthRepository;

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	public <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
		final Claims claims = extractAllClaims(token);
		return claimResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token) {
		return Jwts
				.parserBuilder()
				.setSigningKey(getSignInkey())
				.build()
				.parseClaimsJws(token)
				.getBody();
				
	}

	private Key getSignInkey() {
		byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
		return Keys.hmacShaKeyFor(keyBytes);
	}
	
	public String generateToken(Map<String, Object> extraClaims, User user) {
		extraClaims.put("uuid", user.getUuid());
		return Jwts
				.builder()
				.setClaims(extraClaims)
				.setSubject(user.getEmail())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + getTokenValidity()))
				.signWith(getSignInkey(), SignatureAlgorithm.HS256)
				.compact();
	}
	
	public String generateToken(User user) {
		return generateToken(new HashMap<>(),user);
	}
	
	public boolean isTokenValid(String token) {
		boolean existsByAccessToken = userAuthRepository.existsByAccessToken(token);
		return (existsByAccessToken && !isTokenExpired(token));
	}

	public boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}
	
	public Date extractIssuedAt(String token) {
		return extractClaim(token, Claims::getIssuedAt);
	}

}
