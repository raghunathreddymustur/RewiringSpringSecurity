package com.raghu.security.intro.dao;

import com.raghu.security.intro.ds.Employee;
import org.springframework.data.repository.CrudRepository;

public interface EmployeesDao extends CrudRepository<Employee, Integer> {
}
