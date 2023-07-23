package com.raghu.method.level.security.dao;

import com.raghu.method.level.security.ds.Customer;
import org.springframework.data.repository.CrudRepository;

public interface CustomersDao extends CrudRepository<Customer, Integer> {
}
