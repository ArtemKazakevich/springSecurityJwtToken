package by.kazakevich.springsecurityjwttoken.config;

import by.kazakevich.springsecurityjwttoken.security.JwtConfigurer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
     
     private final JwtConfigurer jwtConfigurer;
     
     public SecurityConfig(JwtConfigurer jwtConfigurer) {
          this.jwtConfigurer = jwtConfigurer;
     }
     
     @Override
     protected void configure(HttpSecurity http) throws Exception {
          http
                  .csrf().disable() // защита от csrf угрозы
                  .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // говорит о том, что сессии не используются
                  .and()
                  .authorizeRequests()
                  .antMatchers("/").permitAll() // даёт доступ любому пользователю по данному адресу
                  .antMatchers("/api/v1/auth/login").permitAll()
                  .anyRequest()
                  .authenticated()
                  .and()
                  .apply(jwtConfigurer); // говорит о том, что аутентификация пользователей проходит на основании конфигурации jwtConfigurer
     }
     
     @Bean
     @Override
     public AuthenticationManager authenticationManagerBean() throws Exception {
          return super.authenticationManagerBean();
     }
     
     // для преобразований паролей
     @Bean
     protected PasswordEncoder passwordEncoder() {
          return new BCryptPasswordEncoder(12);
     }
}
