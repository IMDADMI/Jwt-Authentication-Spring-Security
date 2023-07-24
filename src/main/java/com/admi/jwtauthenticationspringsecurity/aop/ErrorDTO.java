package com.admi.jwtauthenticationspringsecurity.aop;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@AllArgsConstructor
@Data
@Builder
public class ErrorDTO {
    private String message;
}
