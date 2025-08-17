package forohub.API.infra.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import forohub.API.domain.user.User;
import forohub.API.domain.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) throws Exception {
        if (userRepository.findByUsername("usuarioPrueba").isEmpty()) {
            String passwordEncriptada = passwordEncoder.encode("password123");

            User user = new User();
            user.setUsername("usuarioPrueba");
            user.setPassword(passwordEncriptada);

            userRepository.save(user);
            System.out.println("Usuario de prueba creado: usuarioPrueba / password123");
        } else {
            System.out.println("Usuario de prueba ya existe.");
        }
    }
}