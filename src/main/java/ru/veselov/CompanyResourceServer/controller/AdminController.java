package ru.veselov.CompanyResourceServer.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.telegram.telegrambots.meta.api.objects.User;
import ru.veselov.CompanyResourceServer.model.DivisionModel;
import ru.veselov.CompanyResourceServer.service.CustomerService;
import ru.veselov.CompanyResourceServer.service.DivisionService;

import java.util.List;

@RestController
@RequestMapping("/api")
@Slf4j
public class AdminController {

    private final DivisionService divisionService;

    private final CustomerService customerService;
    @Autowired
    public AdminController(DivisionService divisionService, CustomerService customerService) {
        this.divisionService = divisionService;
        this.customerService = customerService;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal Jwt jwt){
        return "Hello "+jwt.getSubject();
    }

    @GetMapping(value = "/divs", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.OK)
    public @ResponseBody List<DivisionModel> getDivisions(){
        return divisionService.findAll();
    }

    @PostMapping(value = "/customer",produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.CREATED)
    public ResponseEntity<?> saveCustomer(@RequestBody User customer){

        log.info("Сохранено {}", customer.getFirstName());
        //customerService.save(customer);
        return new ResponseEntity<>("customer created",HttpStatus.CREATED);
    }
}
