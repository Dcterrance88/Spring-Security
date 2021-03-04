package com.exmov.springsecurity.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import com.google.common.collect.Lists;

import static com.exmov.springsecurity.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{
	
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
		return getApplicationUser()
				.stream()
				.filter(applicationUser -> username.equals(applicationUser.getUsername()))
				.findFirst();
	}
	
	private List<ApplicationUser> getApplicationUser(){
		List<ApplicationUser> applicationUser = Lists.newArrayList(
			new ApplicationUser(
					"annasmith",
					passwordEncoder.encode("password"),
					STUDENT.getGrantedAuthorities(),
					true,
					true,
					true,
					true
			),
			new ApplicationUser(
					"linda",
					passwordEncoder.encode("password"),
					ADMIN.getGrantedAuthorities(),
					true,
					true,
					true,
					true
					),
			new ApplicationUser(
					"tom",
					passwordEncoder.encode("password"),
					ADMINTRAINEE.getGrantedAuthorities(),
					true,
					true,
					true,
					true
					)
			
		);
		return applicationUser;		
	}

}
