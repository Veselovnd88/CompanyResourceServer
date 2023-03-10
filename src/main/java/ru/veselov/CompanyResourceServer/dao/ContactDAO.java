package ru.veselov.CompanyResourceServer.dao;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import ru.veselov.CompanyResourceServer.entity.ContactEntity;


import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.util.List;
import java.util.Optional;

@Repository
@Transactional(readOnly = true)
public class ContactDAO {
    @PersistenceContext
    private final EntityManager entityManager;
    @Autowired
    public ContactDAO(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Transactional
    public void save(ContactEntity contact){
        entityManager.persist(contact);
    }

    public Optional<ContactEntity> findOne(Integer id){
        ContactEntity contactEntity = entityManager.find(ContactEntity.class, id);
        return Optional.ofNullable(contactEntity);
    }
    @SuppressWarnings("unchecked")
    public List<ContactEntity> findAll(){
        return entityManager.createQuery(" SELECT c from ContactEntity c ").getResultList();
    }


}
