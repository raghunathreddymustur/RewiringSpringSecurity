package com.raghu.method.level.security.dao;

import com.raghu.method.level.security.ds.Employee;
import org.springframework.data.repository.CrudRepository;

public interface EmployeesDao extends CrudRepository<Employee, Integer> {
}
