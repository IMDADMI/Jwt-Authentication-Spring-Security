package com.admi.jwtauthenticationspringsecurity.aop;

import com.admi.jwtauthenticationspringsecurity.exceptions.AppException;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;

@ControllerAdvice
public class AuthenticationExceptionHandler {
    @ExceptionHandler(value = {AppException.class})
    @ResponseBody//this annotation let spring take the return type of this method into a body
    //we don't need it if we use the RestControllerAdvice
    public ResponseEntity<ErrorDTO> handleException(AppException appException){
        System.out.println("hmmm");
        //remember that it will be executed only if this exception is thrown in a controller

        return ResponseEntity.status(appException.getStatus()).body(ErrorDTO.builder().message(appException.getMessage()).build());
    }
}
