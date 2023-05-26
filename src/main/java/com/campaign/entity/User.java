package com.campaign.entity;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
@Entity(name="USERS")
public class User {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	@Column(name="USER_ID")
	private long userId;
	
	@Column(name="UUID")
	private String uuid;
	
	@Column(name="EMAIL",unique = true, nullable = false)
	@NotNull
	private String email;
	
	@Column(name="PASSWORD")
	private String password;
	
	@Column(name="FIRST_NAME")
	private String firstName;
	
	@Column(name="LAST_NAME")
	private String lastName;
	
	@Column(name="PHONE_NO")
	private long phoneNo;
	
	@Column(name="LOCATION")
	private String location;
	
	@Column(name="LANGUAGE")
	private String language;
	
	@ManyToMany(cascade = CascadeType.PERSIST, fetch = FetchType.EAGER)
    @JoinTable(name = "USER_ROLE",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();
	
	@Column(name="CREATED_BY")
	private String createdBy;
	
	@Column(name="UPDATED_BY")
	private String updatedBy;
	
	@CreationTimestamp
	@Column(name="CREATED_DATE",updatable = false)
	private Date createdDate;
	
	@UpdateTimestamp
	@Column(name="UPDATED_DATE")
	private Date updatedDate;

		
}
