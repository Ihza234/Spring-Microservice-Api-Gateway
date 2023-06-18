package com.example.demo;




import jakarta.annotation.sql.DataSourceDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;

import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;


@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Autowired
	private DataSource dataSource;


	@Bean
	public UserDetailsService userDetailsService() {
		return new CustomUserDetailsService();
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public DaoAuthenticationProvider authenticationProvider() {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService());
		authProvider.setPasswordEncoder(passwordEncoder());

		return authProvider;
	}


	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/list_users").authenticated()
				.anyRequest().permitAll()
				.and()
				.formLogin()
				.usernameParameter("email")
				.defaultSuccessUrl("/list_users")
				.permitAll()
				.and()
				.logout().logoutSuccessUrl("/").permitAll();

return http.build();


}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration conf) throws Exception {
		return conf.getAuthenticationManager();
	}





}
