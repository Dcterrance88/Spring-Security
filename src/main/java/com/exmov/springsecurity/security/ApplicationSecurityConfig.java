package com.exmov.springsecurity.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

	//note 1
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests() 
			.antMatchers("/", "index", "/css/*, /js/*")
			.permitAll()
			.anyRequest()
			.authenticated()
			.and()
			.httpBasic();
	}
	
	
	
}

/*
 * note 1
 * in this method it was to say that it want to authorized any requests and these request must be authenticated 
 * (the client must be specified id and password) and the mechanism that it want to do enforce this authenticity
 * of a client is by using basic authentication
 * 
 * */
