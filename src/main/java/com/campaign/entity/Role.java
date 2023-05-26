package com.campaign.entity;

import java.util.Date;
import java.util.List;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Entity(name="ROLES")
public class Role {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name="ROLE_ID")
	private long roleId;
	
	@Column(name="UUID")
	private String uuid;
	
	@Column(name="ROLE_NAME", nullable = false)
	@NotNull
	private String roleName;
	
	@Column(name="DESCRIPTION")
	private String description;
	
	@Column(name="IS_SOCIAL")
	private boolean isSocial;
	
	@ManyToMany(mappedBy="roles")
	private List<User> users;
	
	@Column(name="CREATED_BY")
	private String createdBy;
	
	@Column(name="UPDATED_BY")
	private String updatedBy;
	
	@CreationTimestamp
	@Column(name="CREATED_DATE", updatable = false)
	private Date createdDate;
	
	@UpdateTimestamp
	@Column(name="UPDATED_DATE")
	private Date updatedDate;
	
}
