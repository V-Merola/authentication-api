package com.vincenzomerola.auth.services;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.vincenzomerola.auth.dtos.ChangePasswordDto;
import com.vincenzomerola.auth.entities.User;
import com.vincenzomerola.auth.repositories.UserRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;

    @Value("${app.resetPasswordTokenExpirationMinutes}")
    private int resetPasswordTokenExpirationMinutes;

    
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder, JavaMailSender mailSender) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.mailSender = mailSender;
    }

    public List<User> allUsers() {
        List<User> users = new ArrayList<>();

        userRepository.findAll().forEach(users::add);

        return users;
    }
    
    public boolean changePassword(User user, ChangePasswordDto changePasswordDto) {
        if (passwordEncoder.matches(changePasswordDto.getOldPassword(), user.getPassword())) {
            user.setPassword(passwordEncoder.encode(changePasswordDto.getNewPassword()));
            userRepository.save(user);
            return true;
        } else {
            return false;
        }
    }

    //Implementare una protezione, ad esempio email di conferma
    //Il metodo verifica soltanto se l'email è presente nel sistema.
    public String sendPasswordResetToken(String email) {
        Optional<User> userOptional = userRepository.findByEmail(email);
        if (userOptional.isPresent()) {
            User user = userOptional.get();
            String token = UUID.randomUUID().toString();
            user.setResetPasswordToken(token);
            user.setResetPasswordTokenExpiryDate(System.currentTimeMillis() + (resetPasswordTokenExpirationMinutes * 60 * 1000));
            userRepository.save(user);
            //Commentato per effettuare i test
            /*
            SimpleMailMessage mailMessage = new SimpleMailMessage();
            mailMessage.setTo(user.getEmail());
            mailMessage.setSubject("Password Reset Request");
            mailMessage.setText("To reset your password, please click the link below:\n" +
                    "http://localhost:8006/reset-password?token=" + token);

            mailSender.send(mailMessage);
            
            */
            
            // Stampa il token in console
            System.out.println("Password reset token: " + token);
            return token;
        }
        return null;
    }
    //Implementare una protezione, ad esempio email di conferma o altri metodi di validazione
    //implementare un meccanismo che verifichi che il token di reset sia stato richiesto dal legittimo proprietario dell'account. 
    public boolean resetPassword(String token, String newPassword) {
        Optional<User> userOptional = userRepository.findByResetPasswordToken(token);
        if (userOptional.isPresent()) {
            User user = userOptional.get();

              // Controlla che l'utente autenticato sia lo stesso di quello che sta cercando di resettare la password
            if (!user.equals(authenticatedUser)) {
                throw new AccessDeniedException("You are not allowed to reset another user's password");
            }
            if (user.getResetPasswordTokenExpiryDate() > System.currentTimeMillis()) {
                user.setPassword(passwordEncoder.encode(newPassword));
                user.setResetPasswordToken(null);
                user.setResetPasswordTokenExpiryDate(null);
                userRepository.save(user);
                return true;
            }
        }
        return false;
    }
}
