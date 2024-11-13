package com.iits.main.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.iits.main.entity.Product;
import com.iits.main.service.ProductService;


@RestController
@RequestMapping("/api/")
@CrossOrigin("*")
public class MyProductController {

	@Autowired
	ProductService productService;
	
	
	@PostMapping("products")
	public ResponseEntity<Product> saveProduct(@RequestBody Product product) {
		/*
		 * 1. Status Code : 1xx ,2xx, 3xx, 4xx, 5xx
		 * 	  201 - Created
		 *    204 - No Content
		 * 2. Headers :   Content Type
		 * 
		 * 3. Body    :   Objects  or Error Messages
		 */
		 Product p=this.productService.save(product);
		/* return ResponseEntity.ok()
				 			  .header("myheader", "somevalue")
				 			  .contentType(MediaType.APPLICATION_XML)
				 			  .body(p);
		*/
		 //return ResponseEntity.ok(p);
		 ResponseEntity<Product> rs=new ResponseEntity<Product>(p, HttpStatus.CREATED);
		 return rs;
	}
	
	@GetMapping("products/{id}")
	public ResponseEntity<Product> getProductById(@PathVariable("id") int id){
		 Product p=this.productService.findById(id);
		 return new ResponseEntity<Product>(p,HttpStatus.OK);
	}
	
	
	@GetMapping("products")
	public List<Product> findProducts(){
		return this.productService.findAllProducts();
	}
	
	
	@DeleteMapping("products/{id}")
	public ResponseEntity<String> deleteProductById(@PathVariable("id") int id){
		  this.productService.deleteById(id);
		  return new ResponseEntity<String>("SUCCESSFULLY DELETED",HttpStatus.OK);
	}
	
	@PutMapping("products/{id}")
	public ResponseEntity<Product> putMethodName(@PathVariable int id, @RequestBody Product product) {
		  Product p= this.productService.updateProduct(product);
		
		return new ResponseEntity<Product>(p,HttpStatus.OK);
	}
	
}
