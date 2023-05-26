package com.campaign.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.campaign.entity.UserAuth;

@Repository
public interface UserAuthRepository extends JpaRepository<UserAuth, Long>{

	boolean existsByAccessToken(String token);

}
