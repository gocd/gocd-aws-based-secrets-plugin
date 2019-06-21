package com.thoughtworks.gocd.secretmanager.aws.validators;

import com.github.bdpiparva.plugin.base.validation.ValidationResult;
import com.github.bdpiparva.plugin.base.validation.Validator;
import com.thoughtworks.gocd.secretmanager.aws.AWSCredentialsProviderChain;
import com.thoughtworks.gocd.secretmanager.aws.exceptions.AWSCredentialsException;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;

import java.util.Map;

import static com.github.bdpiparva.plugin.base.executors.Executor.GSON;
import static com.github.bdpiparva.plugin.base.executors.Executor.LOGGER;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.ACCESS_KEY;
import static com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig.SECRET_ACCESS_KEY;
import static org.apache.commons.lang3.StringUtils.isBlank;

public class CredentialValidator implements Validator {
    private final AWSCredentialsProviderChain credentialsProviderChain = new AWSCredentialsProviderChain();

    @Override
    public ValidationResult validate(Map<String, String> requestBody) {
        ValidationResult validationResult = new ValidationResult();
        try {
            credentialsProviderChain.autoDetectAWSCredentials();
            return validationResult;
        } catch (AWSCredentialsException e) {
            LOGGER.info(e.getMessage());
        }

        SecretConfig secretConfig = GSON.fromJson(GSON.toJson(requestBody), SecretConfig.class);

        if (isBlank(secretConfig.getAwsAccessKey())) {
            validationResult.add(ACCESS_KEY, "Must not be blank.");
        }

        if (isBlank(secretConfig.getAwsSecretAccessKey())) {
            validationResult.add(SECRET_ACCESS_KEY, "Must not be blank.");
        }

        return validationResult;
    }
}
