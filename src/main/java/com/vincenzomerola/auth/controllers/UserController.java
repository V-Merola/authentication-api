package com.vincenzomerola.auth.controllers;


import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vincenzomerola.auth.dtos.ChangePasswordDto;
import com.vincenzomerola.auth.dtos.ForgotPasswordDto;
import com.vincenzomerola.auth.dtos.ResetPasswordDto;
import com.vincenzomerola.auth.entities.User;
import com.vincenzomerola.auth.services.UserService;

import java.util.List;

@RequestMapping("/auth/users")
@RestController
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public ResponseEntity<User> authenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        User currentUser = (User) authentication.getPrincipal();

        return ResponseEntity.ok(currentUser);
    }

    @GetMapping("admin/all")
    //@PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> allUsers() {
        List <User> users = userService.allUsers();

        return ResponseEntity.ok(users);
    }
    
    @PutMapping("/me/change-password")
    public ResponseEntity<?> changePassword(@RequestBody ChangePasswordDto changePasswordDto) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User currentUser = (User) authentication.getPrincipal();

        boolean success = userService.changePassword(currentUser, changePasswordDto);

        if (success) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.badRequest().body("Old password is incorrect");
        }
    }
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestBody ForgotPasswordDto forgotPasswordDto) {
        String token = userService.sendPasswordResetToken(forgotPasswordDto.getEmail());
        if (token != null) {
            return ResponseEntity.ok().body("Password reset token: " + token);
        } else {
            return ResponseEntity.badRequest().body("Email not found");
        }
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestBody ResetPasswordDto resetPasswordDto) {
        boolean success = userService.resetPassword(resetPasswordDto.getToken(), resetPasswordDto.getNewPassword());

        if (success) {
            return ResponseEntity.ok().build();
        } else {
            return ResponseEntity.badRequest().body("Invalid or expired token");
        }
    }
}
