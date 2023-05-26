package com.campaign.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig{
	
    @Autowired
    private CustomAuthSuccessHandler customAuthSuccessHandler;
    
    @Autowired
    private TokenAuthenticationFilter tokenAuthenticationFilter;
    
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	 http
    	 .authorizeHttpRequests()
    	 .requestMatchers("/").permitAll()
    	 .requestMatchers(HttpMethod.POST, "/auth/**").permitAll()
    	 .requestMatchers(HttpMethod.POST, "/users").permitAll()
    	 .requestMatchers("/auth/**").permitAll()
    	 .anyRequest().authenticated().and()
         .oauth2Login(oauth2Login -> oauth2Login
                 .successHandler(customAuthSuccessHandler))
         .sessionManagement(sessionManagement -> sessionManagement
                 .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
         .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
         .logout(logout -> logout
                 .logoutUrl("/logout")
                 .deleteCookies("JSESSIONID"))
         .csrf().disable();
     
    	return http.build();
    }
    
//	public LogoutSuccessHandler azureAdLogoutHandler() {
//        return (request, response, authentication) -> {
//            try {
//                response.sendRedirect("https://login.microsoftonline.com/a40ee758-1021-4d42-b0f0-f4f554472af6/oauth2/logout");
//            } catch (IOException e) {
//                throw new RuntimeException(e);
//            }
//        };
//    }
    
}

