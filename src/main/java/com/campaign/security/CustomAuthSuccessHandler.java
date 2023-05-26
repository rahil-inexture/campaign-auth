package com.campaign.security;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.campaign.entity.Role;
import com.campaign.entity.User;
import com.campaign.entity.UserAuth;
import com.campaign.repository.RoleRepository;
import com.campaign.repository.UserAuthRepository;
import com.campaign.repository.UserRepository;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CustomAuthSuccessHandler  implements AuthenticationSuccessHandler {
	
	static final Logger log = LoggerFactory.getLogger(CustomAuthSuccessHandler.class);
	
	@Autowired
	private UserAuthRepository userAuthRepository;
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;

    private final OAuth2AuthorizedClientService clientService;

    public CustomAuthSuccessHandler(OAuth2AuthorizedClientService clientService) {
        this.clientService = clientService;
    }

	@Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2AuthorizedClient client = clientService.loadAuthorizedClient(
                oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName());

        OAuth2AuthenticatedPrincipal principal = oauthToken.getPrincipal();        
        String email = principal.getAttribute("preferred_username");
        
        Set<String> roles = oauthToken.getAuthorities().stream()
                .filter(authority -> authority.getAuthority().startsWith("OIDC_") || authority.getAuthority().startsWith("ROLE_"))
                .map(e -> e.getAuthority().split("_")[1])
                .collect(Collectors.toSet());
        log.info("roles:"+roles);        
        
        
        String accessToken = client.getAccessToken().getTokenValue();
        String refreshToken = client.getRefreshToken().getTokenValue();
        Instant expiresAt = client.getAccessToken().getExpiresAt();
        Instant issuedAt = client.getAccessToken().getIssuedAt();

    	Set<Role> rolesSet = new HashSet<>();
    	roles.stream()
        .filter(role -> !roleRepository.existsByRoleName(role))
        .forEach(role -> {
            Role roleEntity = new Role();
            roleEntity.setRoleName(role);
            roleEntity.setSocial(true);
            roleEntity.setUuid(UUID.randomUUID().toString());
            rolesSet.add(roleEntity);  
        });
    	
    	Optional<User> optionalUser = userRepository.findByEmail(email);
    	User user;
    	if(optionalUser.isPresent()) {
    		user = optionalUser.get();	
    	}else {
    		user = new User();
    		user.setUuid(UUID.randomUUID().toString());
    		user.setEmail(email);
    	}
    	user.getRoles().addAll(rolesSet);
    	userRepository.save(user);
    	
    	UserAuth userAuth = new UserAuth();
    	userAuth.setUserId(user.getUserId());
        userAuth.setAccessToken(accessToken);
        userAuth.setRefreshToken(refreshToken);
        userAuth.setExpiresAt(Date.from(expiresAt));
        userAuth.setIssuedAt(Date.from(issuedAt));
        userAuth.setUuid(UUID.randomUUID().toString());
    	userAuthRepository.save(userAuth);
    
        response.sendRedirect("/");

    }

}
