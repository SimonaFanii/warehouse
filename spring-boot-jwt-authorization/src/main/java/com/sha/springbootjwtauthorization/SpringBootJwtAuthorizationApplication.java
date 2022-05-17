package com.sha.springbootjwtauthorization;

import com.mysql.cj.Session;
import com.mysql.cj.xdevapi.SessionFactory;
import com.sha.springbootjwtauthorization.model.User;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.Query;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringBootJwtAuthorizationApplication {



	public static void main(String[] args) {
		SpringApplication.run(SpringBootJwtAuthorizationApplication.class, args);}
}

