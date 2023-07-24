package com.admi.jwtauthenticationspringsecurity.exceptions;


import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class AppException extends RuntimeException{
    private HttpStatus status;
    public AppException(String message, HttpStatus status){
        super(message);
        this.status = status;
    }
}
