package com.exmov.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import static com.exmov.springsecurity.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	
	
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	//note 1
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests() 
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
			.roles(STUDENT.name()) // ROLE_STUDENT
			.build();
		
		UserDetails lindaUser = User.builder()
			.username("linda")
			.password(passwordEncoder.encode("password123"))
			.roles(ADMIN.name())
			.build();
		return new InMemoryUserDetailsManager(
				annaSmithUser,
				lindaUser
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
