package ru.veselov.CompanyResourceServer.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import ru.veselov.CompanyResourceServer.model.DivisionModel;
import ru.veselov.CompanyResourceServer.service.DivisionService;

import java.util.List;

@RestController
@RequestMapping("/company")
@Slf4j
public class BotController {

    private final DivisionService divisionService;


    public BotController(DivisionService divisionService) {
        this.divisionService = divisionService;
    }
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(value = HttpStatus.OK)
    public @ResponseBody List<DivisionModel> getDivisions(){
        return divisionService.findAll();
    }


}
