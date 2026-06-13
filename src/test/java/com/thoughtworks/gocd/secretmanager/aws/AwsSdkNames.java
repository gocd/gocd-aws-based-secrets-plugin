package com.thoughtworks.gocd.secretmanager.aws;

import software.amazon.awssdk.core.SdkSystemSetting;

public class AwsSdkNames {
    public static final String ACCESS_KEY_ENV_VAR = "AWS_ACCESS_KEY_ID";
    public static final String SECRET_KEY_ENV_VAR = "AWS_SECRET_ACCESS_KEY";
    public static final String ACCESS_KEY_SYSTEM_PROPERTY = SdkSystemSetting.AWS_ACCESS_KEY_ID.property();
    public static final String SECRET_KEY_SYSTEM_PROPERTY = SdkSystemSetting.AWS_SECRET_ACCESS_KEY.property();
}
