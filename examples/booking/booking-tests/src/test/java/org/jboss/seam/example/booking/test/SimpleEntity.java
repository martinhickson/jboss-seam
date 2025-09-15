package org.jboss.seam.example.booking.test;

import jakarta.persistence.*;

/**
 * Simple JPA entity for testing basic persistence operations in WildFly 36.
 */
@Entity
@Table(name = "simple_entity")
public class SimpleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "name")
    private String name;

    public SimpleEntity() {
    }

    public SimpleEntity(String name) {
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return "SimpleEntity{" +
                "id=" + id +
                ", name='" + name + '\'' +
                '}';
    }
}
