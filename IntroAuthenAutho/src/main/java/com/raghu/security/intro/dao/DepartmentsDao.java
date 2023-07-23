package com.raghu.security.intro.dao;

import com.raghu.security.intro.ds.Department;
import org.springframework.data.repository.CrudRepository;

public interface DepartmentsDao extends CrudRepository<Department, Integer> {
}
