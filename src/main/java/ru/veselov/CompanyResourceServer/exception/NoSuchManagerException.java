package ru.veselov.CompanyResourceServer.exception;

public class NoSuchManagerException extends Exception{

    public NoSuchManagerException(){
        super("No manager with such Id in database");
    }
}
