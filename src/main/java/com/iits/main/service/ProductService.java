package com.iits.main.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.iits.main.entity.Product;
import com.iits.main.exception.ResourceNotFoundException;
import com.iits.main.repository.ProductRepository;

@Service
public class ProductService implements ProductDAO {

	@Autowired
	ProductRepository productRepository;

	@Override
	public Product save(Product product) {
		return this.productRepository.save(product);

	}

	@Override
	public Product findById(int pid) {
		return this.productRepository
				  .findById(pid)
				  .orElseThrow(() -> new ResourceNotFoundException("PRODUCT NOT FOUND"));

	}

	@Override
	public Product findByName(String name) {
		return this.productRepository.findByNameUsingJPQL(name);

	}

	@Override
	public List<Product> findAllProducts() {
		return this.productRepository.findAll();

	}

	@Override
	public Product updateProduct(Product product) {
		Optional<Product> op = this.productRepository.findById(product.getId());
		if (op.isPresent()) {
			Product p = op.get();
			return this.productRepository.save(product);
		}
		return null;
	}

	@Override
	public void deleteById(int id) {
		this.productRepository.deleteById(id);
	}

}
