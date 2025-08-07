package com.aishwarya.base.repository;

import com.aishwarya.base.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;


public interface RoleRepo extends JpaRepository<Role, Long> {
}
