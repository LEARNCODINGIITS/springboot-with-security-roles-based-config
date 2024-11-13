package com.iits.main.service;

import java.util.List;

import com.iits.main.entity.Product;

public interface ProductDAO {
 Product save(Product product);
 Product findById(int pid);
 Product findByName(String name);
 List<Product> findAllProducts();
 Product updateProduct(Product product);
 void deleteById(int id);
 
}
