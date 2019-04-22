/*
 * Copyright 2019 ThoughtWorks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.thoughtworks.gocd.secretmanager.aws.models;

import com.github.bdpiparva.plugin.base.annotations.Property;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import java.util.Objects;

public class SecretConfig {
    @Expose
    @SerializedName("endpoint")
    @Property(name = "Endpoint", required = true)
    private String awsEndpoint;

    @Expose
    @SerializedName("access_key")
    @Property(name = "AccessKey", required = true, secure = true)
    private String awsAccessKey;

    @Expose
    @SerializedName("secret_access_key")
    @Property(name = "SecretAccessKey", required = true, secure = true)
    private String awsSecretAccessKey;

    @Expose
    @SerializedName("region")
    @Property(name = "Region", required = true)
    private String region;

    @Expose
    @SerializedName("secret_name")
    @Property(name = "SecretName", required = true)
    private String secretName;

    public String getSecretName() {
        return secretName;
    }

    public String getAwsAccessKey() {
        return awsAccessKey;
    }

    public String getAwsSecretAccessKey() {
        return awsSecretAccessKey;
    }

    public String getRegion() {
        return region;
    }

    public String getAwsEndpoint() {
        return awsEndpoint;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SecretConfig that = (SecretConfig) o;
        return Objects.equals(awsEndpoint, that.awsEndpoint) &&
                Objects.equals(awsAccessKey, that.awsAccessKey) &&
                Objects.equals(awsSecretAccessKey, that.awsSecretAccessKey) &&
                Objects.equals(region, that.region) &&
                Objects.equals(secretName, that.secretName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(awsEndpoint, awsAccessKey, awsSecretAccessKey, region, secretName);
    }
}