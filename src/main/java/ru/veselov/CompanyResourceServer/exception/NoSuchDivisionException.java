package ru.veselov.CompanyResourceServer.exception;

public class NoSuchDivisionException extends Exception{

    public NoSuchDivisionException(){
        super("No division found with such ID");
    }
}
