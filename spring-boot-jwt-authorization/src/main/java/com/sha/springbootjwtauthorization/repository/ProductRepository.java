package com.sha.springbootjwtauthorization.repository;

import com.sha.springbootjwtauthorization.model.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductRepository extends JpaRepository<Product, Long>
{
}