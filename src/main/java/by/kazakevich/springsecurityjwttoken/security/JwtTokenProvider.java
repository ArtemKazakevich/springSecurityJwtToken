package by.kazakevich.springsecurityjwttoken.security;

import by.kazakevich.springsecurityjwttoken.exception.JwtAuthenticationException;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtTokenProvider {
     
     private final UserDetailsService userDetailsService;
     
     @Value("${jwt.secret}") // берется из application.properties
     private String secretKey;
     
     @Value("${jwt.expiration}") // берется из application.properties
     private long validityInMilliseconds;
     
     @Value("${jwt.header}") // берется из application.properties
     private String authorizationHeader; // заголовок запросов в котором хранится наш токен
     
     public JwtTokenProvider(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
          this.userDetailsService = userDetailsService;
     }
     
     // шифрует в строку наш ключ
     @PostConstruct
     protected void init() {
          secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
     }
     
     // создание token на основании данных, которые передаются (userName, role)
     public String createToken(String userName, String role) {
          Claims claims = Jwts.claims().setSubject(userName);
          claims.put("role", role);
          Date now = new Date(); // для присвоения даты создания token
          Date validity = new Date(now.getTime() + validityInMilliseconds * 1000); // дата истечения срока token
          
          // получение token
          return Jwts.builder()
                  .setClaims(claims)
                  .setIssuedAt(now)
                  .setExpiration(validity)
                  .signWith(SignatureAlgorithm.ES256, secretKey) // кодировка token + secretKey-секретный ключ для кодировки
                  .compact();
     }
     
     
     // валидация token. валидация – это проверка правильности token
     public boolean validateToken(String token) {
          try {
               Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
               return !claimsJws.getBody().getExpiration().before(new Date());// проверяет истек ли срок нашего token или нет
          } catch (JwtException | IllegalArgumentException e) {
               throw  new JwtAuthenticationException("JWT token is expired or invalid", HttpStatus.UNAUTHORIZED);
          }
     }
     
     // получение аутентификации
     public Authentication getAuthentication(String token) {
          UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUserName(token));
          return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
     }
     
     // получение userName
     public String getUserName(String token) {
          return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
     }
     
     // получение token из нашего запроса
     public String resolveToken(HttpServletRequest request) {
          return request.getHeader(authorizationHeader);
     }
}
