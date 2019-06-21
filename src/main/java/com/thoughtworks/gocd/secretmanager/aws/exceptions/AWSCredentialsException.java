package com.thoughtworks.gocd.secretmanager.aws.exceptions;

public class AWSCredentialsException extends RuntimeException {
    public AWSCredentialsException(String message) {
        super(message);
    }
}
