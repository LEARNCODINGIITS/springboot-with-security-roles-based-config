package com.iits.main.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import com.iits.main.entity.Product;

@Repository
public interface ProductRepository extends JpaRepository<Product,Integer> {

	
		//JPQL: Java Persistence Query Language
	   @Query("Select p from Product p where p.name=?1")
	   Product findByNameUsingJPQL(String name);
	   
	   //Native Query
	   @Query(value="select * from product where price=?1",nativeQuery = true)
	   List<Product> findByPriceUsingNativeQuery(Double price);	
	   
	   //By using named parameters
	   @Query("select p from Product p where p.name=:name or p.price=:price")
	   List<Product> findByNameOrPrice(@Param("name") String name,@Param("price") Double price);
	   
	   
	   
	   
	   
}
