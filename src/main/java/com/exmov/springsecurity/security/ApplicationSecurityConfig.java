package com.exmov.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import static com.exmov.springsecurity.security.ApplicationUserRole.*;
//import static com.exmov.springsecurity.security.ApplicationUserPermission.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	//note 1
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
//			.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//			.and()
			.csrf().disable()
			.authorizeRequests()			
			.antMatchers("/", "index", "/css/*, /js/*").permitAll()
			.antMatchers("/api/**").hasRole(STUDENT.name())
			.anyRequest()
			.authenticated()
			.and()
			.httpBasic();
	}

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		UserDetails annaSmithUser = User.builder()
			.username("annasmith")
			.password(passwordEncoder.encode("password"))
//			.roles(STUDENT.name()) // ROLE_STUDENT
			.authorities(STUDENT.getGrantedAuthorities())
			.build();
		
		UserDetails lindaUser = User.builder()
			.username("linda")
			.password(passwordEncoder.encode("password123"))
//			.roles(ADMIN.name()) // ROLE_ADMIN
			.authorities(ADMIN.getGrantedAuthorities())
			.build();
		
		UserDetails tomUser = User.builder()
			.username("tom")
			.password(passwordEncoder.encode("password123"))
//			.roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
			.authorities(ADMINTRAINEE.getGrantedAuthorities())
			.build();
		return new InMemoryUserDetailsManager(
				annaSmithUser,
				lindaUser,
				tomUser
		);
	}
	
	
	
		
}

/*
 * note 1
 * in this method it was to say that it want to authorized any requests and these request must be authenticated 
 * (the client must be specified id and password) and the mechanism that it want to do enforce this authenticity
 * of a client is by using basic authentication.
 * 
 * with the antMatchers method we can set the paths that don't need authentication and them the "permitAll"
 * method gives the permission
 * 
 * 
 * */
