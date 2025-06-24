package project.ai.myhealth.service.user;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import project.ai.myhealth.dto.custom.UserDetailsCustom;
import project.ai.myhealth.entity.User;
import project.ai.myhealth.repository.UserRepository;
import project.ai.myhealth.utilities.Constants;

import java.util.List;
import java.util.Objects;

@Slf4j
@Service
public class UserServiceImpl implements UserService, UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username).orElseThrow(() -> new UsernameNotFoundException("User not found !!!"));
        String role = (Objects.equals(user.getRole(), Constants.ROLE_USER)) ? "ROLE_USER" : "ROLE_ADMIN";
        List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));
        return new UserDetailsCustom(user, authorities);
    }
}
