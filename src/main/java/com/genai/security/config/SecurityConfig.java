package com.genai.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // CSRF remains enabled, including on the deliberately vulnerable lab endpoints.
        return http
                .authorizeHttpRequests(auth ->
                        auth.anyRequest().authenticated())
                .formLogin(form -> form
                        .defaultSuccessUrl("/", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )
                .build();
    }

    @Bean
    UserDetailsService users() {
        var encoder = new BCryptPasswordEncoder();
        return new InMemoryUserDetailsManager(
                User.withUsername("alice").password("{bcrypt}" +
                        encoder.encode("lab-password")).roles("CUSTOMER").build(),
                User.withUsername("bob").password("{bcrypt}" +
                        encoder.encode("lab-password")).roles("CUSTOMER").build());
    }
}
