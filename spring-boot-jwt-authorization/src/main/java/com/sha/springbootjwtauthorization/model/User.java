package com.sha.springbootjwtauthorization.model;

import lombok.Data;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@Entity
@Table(name="users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name="username", unique=true, nullable=false, length=100)
    private String username;

    @Column(name="password",nullable=true)
    private String password;

    @Column(name="name", nullable=true)
    private String name;

    @Column(name="create_time", nullable=true)
    private LocalDateTime creationTime;

    @Enumerated(EnumType.STRING)
    @Column(name="role",nullable=true)
    private Role role;

    @Transient
    private  String accessToken;

    @Transient
    private  String refreshToken;

}
