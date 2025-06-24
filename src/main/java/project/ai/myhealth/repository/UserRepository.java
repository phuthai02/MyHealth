package project.ai.myhealth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import project.ai.myhealth.entity.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
}
