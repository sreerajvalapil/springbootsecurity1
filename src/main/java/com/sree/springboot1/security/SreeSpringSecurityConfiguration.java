package com.sree.springboot1.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SreeSpringSecurityConfiguration extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("sreeraj")
                .password("123")
                .roles("ADMIN")
                .and()
                .withUser("sajana")
                .password("123")
                .roles("USER")
                .and()
                .withUser("sreyaan")
                .password("123")
                .roles("CHILD");

    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

   /*The order of the URL matchers affects here , The least restrictive one should be at the top
    , then it follows the order */
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeRequests()
                .antMatchers("/sree/**").hasRole("ADMIN")
                .antMatchers("/saj/**").hasRole("USER")
                .antMatchers("/sreyaan/**").hasRole("CHILD")
                .antMatchers("/").permitAll()
                .and().formLogin();
    }


}
