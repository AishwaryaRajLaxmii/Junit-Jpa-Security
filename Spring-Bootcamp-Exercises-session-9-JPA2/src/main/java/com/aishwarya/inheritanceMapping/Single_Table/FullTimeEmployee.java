package com.aishwarya.inheritanceMapping.Single_Table;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;

@Entity
@DiscriminatorValue("FULL_TIME")
public class FullTimeEmployee extends Employee {
    private double salary;
}
