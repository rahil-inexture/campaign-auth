package com.campaign.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.campaign.entity.Role;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long>{

	boolean existsByRoleName(String role);

}
