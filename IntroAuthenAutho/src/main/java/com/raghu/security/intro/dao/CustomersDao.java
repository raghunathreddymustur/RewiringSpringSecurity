package com.raghu.security.intro.dao;

import com.raghu.security.intro.ds.Customer;
import org.springframework.data.repository.CrudRepository;

public interface CustomersDao extends CrudRepository<Customer, Integer> {
}
