package ru.veselov.CompanyResourceServer.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.telegram.telegrambots.meta.api.objects.Message;
import ru.veselov.CompanyResourceServer.dao.CustomerDAO;
import ru.veselov.CompanyResourceServer.dao.DivisionDAO;
import ru.veselov.CompanyResourceServer.dao.InquiryDAO;
import ru.veselov.CompanyResourceServer.entity.Customer;
import ru.veselov.CompanyResourceServer.entity.CustomerMessageEntity;
import ru.veselov.CompanyResourceServer.entity.Division;
import ru.veselov.CompanyResourceServer.entity.Inquiry;
import ru.veselov.CompanyResourceServer.model.InquiryModel;


import java.util.Date;
import java.util.List;
import java.util.Optional;

@Service
@Slf4j
public class InquiryService {
    private final InquiryDAO inquiryDAO;
    private final CustomerDAO customerDAO;
    private final DivisionDAO divisionDAO;
    @Autowired
    public InquiryService(InquiryDAO inquiryDAO, CustomerDAO customerDAO, DivisionDAO divisionDAO) {
        this.inquiryDAO = inquiryDAO;
        this.customerDAO = customerDAO;
        this.divisionDAO = divisionDAO;
    }

    public Inquiry save(InquiryModel inquiry){
        Optional<Customer> customerEntity = customerDAO.findOne(inquiry.getUserId());
        Optional<Division> divisionOptional = divisionDAO.findOne(inquiry.getDivision().getDivisionId());
        if(customerEntity.isPresent()&&divisionOptional.isPresent()){
            Inquiry inquiryEntity = toInquiryEntity(inquiry);
            inquiryEntity.setCustomer(customerEntity.get());
            inquiryEntity.setDivision(divisionOptional.get());
            log.info("{}: запрос пользователя сохранен в БД",inquiry.getUserId());
            return inquiryDAO.save(inquiryEntity);
        }

        else{
            log.info("{}: запрос не сохранен, т.к. в бд нет клиента или отдела",inquiry.getUserId());
            return null;}
    }
    public Optional<Inquiry> findWithMessages(Integer id){
        return inquiryDAO.findOneWithMessages(id);
    }

    public List<Inquiry> findAll(){
        return inquiryDAO.findAll();
    }

    private Inquiry toInquiryEntity(InquiryModel inquiryModel){
        Inquiry inquiry = new Inquiry();
        inquiry.setDate(new Date());
        for(Message message: inquiryModel.getMessages()){
            CustomerMessageEntity cme = new CustomerMessageEntity();
            cme.setMessage(message);
            inquiry.addMessage(cme);
        }
        return inquiry;
    }
}
