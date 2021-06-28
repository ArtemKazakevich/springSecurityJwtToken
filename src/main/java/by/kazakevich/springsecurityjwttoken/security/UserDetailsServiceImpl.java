package by.kazakevich.springsecurityjwttoken.security;

import by.kazakevich.springsecurityjwttoken.model.User;
import by.kazakevich.springsecurityjwttoken.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("userDetailsServiceImpl")
public class UserDetailsServiceImpl implements UserDetailsService {
     
     private final UserRepository userRepository;
     
     @Autowired
     public UserDetailsServiceImpl(UserRepository userRepository) {
          this.userRepository = userRepository;
     }
     
     // возвращает user по email пользователя из БД
     @Override
     public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
          User user = userRepository.findByEmail(email).orElseThrow(() ->
                  new UsernameNotFoundException("User doesn't exists"));
          return SecurityUser.fromUser(user);
     }
}