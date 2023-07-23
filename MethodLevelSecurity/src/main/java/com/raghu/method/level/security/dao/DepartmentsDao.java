package com.raghu.method.level.security.dao;


import com.raghu.method.level.security.ds.Department;
import org.springframework.data.repository.CrudRepository;

public interface DepartmentsDao extends CrudRepository<Department, Integer> {
}
