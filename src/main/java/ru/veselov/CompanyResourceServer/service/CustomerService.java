package ru.veselov.CompanyResourceServer.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.telegram.telegrambots.meta.api.objects.User;
import ru.veselov.CompanyResourceServer.dao.ContactDAO;
import ru.veselov.CompanyResourceServer.dao.CustomerDAO;
import ru.veselov.CompanyResourceServer.entity.ContactEntity;
import ru.veselov.CompanyResourceServer.entity.Customer;
import ru.veselov.CompanyResourceServer.model.ContactModel;


import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class CustomerService {
    private final CustomerDAO customerDAO;
    private final ContactDAO contactDAO;

    @Autowired
    public CustomerService(CustomerDAO customerDAO, ContactDAO contactDAO) {
        this.customerDAO = customerDAO;
        this.contactDAO = contactDAO;
    }

    public void save(User user){
        Optional<Customer> one = findOne(user.getId());
        if(one.isEmpty()){
            customerDAO.save(toCustomer(user));
            log.info("{}: новый пользователь  сохранен в БД", user.getId());}
        else{
            customerDAO.update(toCustomer(user));
            log.info("{}: данные пользователя  обновлены в БД", user.getId());
        }
    }


    public Optional<Customer> findOne(Long userId){
        return customerDAO.findOne(userId);
    }
    public Optional<Customer> findOneWithContacts(Long userId){
        return customerDAO.findOneWithContacts(userId);
    }
    public void remove(User user){
        customerDAO.deleteById(user.getId());
    }
    public List<Customer> findAll(){
        return customerDAO.findAll();
    }
    //@Transactional
    public void saveContact(ContactModel contact){
        Optional<Customer> one = customerDAO.findOneWithContacts(contact.getUserId());
        if(one.isPresent()){
            ContactEntity contactEntity = toContactEntity(contact);
            contactEntity.setCustomer(one.get());
            contactDAO.save(contactEntity);
        }
        log.info("{}: новый контакт  сохранен в БД", contact.getUserId());
    }
    private Customer toCustomer(User user){
        Customer customer = new Customer();
        customer.setId(user.getId());
        customer.setFirstName(user.getFirstName());
        customer.setLastName(user.getLastName());
        customer.setUserName(user.getUserName());
        return customer;
    }

    private ContactEntity toContactEntity(ContactModel contact){
        ContactEntity contactEntity = new ContactEntity();
        contactEntity.setContact(contact.getContact());
        contactEntity.setEmail(contact.getEmail());
        contactEntity.setFirstName(contact.getFirstName());
        contactEntity.setPhone(contact.getPhone());
        contactEntity.setFirstName(contact.getFirstName());
        contactEntity.setLastName(contact.getLastName());
        return contactEntity;
    }
}
