package by.kazakevich.springsecurityjwttoken.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

// используется для того, чтобы вставить наш JwtTokenFilter в самое начало проверок, чтобы обрабатывать наш token из запросов
@Component
public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
     
     private final JwtTokenFilter jwtTokenFilter;
     
     public JwtConfigurer(JwtTokenFilter jwtTokenFilter) {
          this.jwtTokenFilter = jwtTokenFilter;
     }
     
     @Override
     public void configure(HttpSecurity httpSecurity) throws Exception {
          httpSecurity.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
     }
}
