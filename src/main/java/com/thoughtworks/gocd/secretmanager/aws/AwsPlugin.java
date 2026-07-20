/*
 * Copyright 2022 Thoughtworks, Inc.
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

package com.thoughtworks.gocd.secretmanager.aws;

import cd.go.plugin.base.dispatcher.BaseBuilder;
import cd.go.plugin.base.dispatcher.RequestDispatcher;
import com.thoughtworks.go.plugin.api.GoApplicationAccessor;
import com.thoughtworks.go.plugin.api.GoPlugin;
import com.thoughtworks.go.plugin.api.GoPluginIdentifier;
import com.thoughtworks.go.plugin.api.annotation.Extension;
import com.thoughtworks.go.plugin.api.exceptions.UnhandledRequestTypeException;
import com.thoughtworks.go.plugin.api.logging.Logger;
import com.thoughtworks.go.plugin.api.request.DefaultGoApiRequest;
import com.thoughtworks.go.plugin.api.request.GoPluginApiRequest;
import com.thoughtworks.go.plugin.api.response.GoApiResponse;
import com.thoughtworks.go.plugin.api.response.GoPluginApiResponse;
import com.thoughtworks.gocd.secretmanager.aws.models.SecretConfig;
import com.thoughtworks.gocd.secretmanager.aws.models.ServerInfo;
import com.thoughtworks.gocd.secretmanager.aws.validators.CredentialValidator;

import static java.util.Collections.singletonList;

@Extension
public class AwsPlugin implements GoPlugin {
    public final static Logger LOGGER = Logger.getLoggerFor(AwsPlugin.class);
    private static final GoPluginIdentifier PLUGIN_IDENTIFIER = new GoPluginIdentifier("secrets", singletonList("1.0"));
    private static final String REQUEST_SERVER_INFO = "go.processor.server-info.get";

    private static volatile GoApplicationAccessor goApplicationAccessor;
    private static volatile String serverId;

    private RequestDispatcher requestDispatcher;

    @Override
    public void initializeGoApplicationAccessor(GoApplicationAccessor goApplicationAccessor) {
        // Capture the accessor only; do NOT query the server here. The GoCD server may not yet be ready to
        // answer processor requests during plugin initialization, so the server id is resolved lazily on first use.
        AwsPlugin.goApplicationAccessor = goApplicationAccessor;
        requestDispatcher = BaseBuilder
                .forSecrets()
                .v1()
                .icon("/plugin-icon.png", "image/png")
                .configMetadata(SecretConfig.class)
                .configView("/secrets.template.html")
                .validateSecretConfig(new CredentialValidator())
                .lookup(new SecretConfigLookupExecutor())
                .build();
    }

    /**
     * The unique id GoCD generated for this server, resolved lazily and cached on first success. Returns
     * {@code null} if it cannot (yet) be determined, in which case callers simply proceed without it - e.g.
     * the STS assume-role flow omits the {@code sts:ExternalId} condition value.
     */
    public static String getServerId() {
        if (serverId == null) {
            serverId = fetchServerId();
        }
        return serverId;
    }

    private static String fetchServerId() {
        GoApplicationAccessor accessor = goApplicationAccessor;
        if (accessor == null) {
            return null;
        }
        try {
            GoApiResponse response = accessor.submit(new DefaultGoApiRequest(REQUEST_SERVER_INFO, "1.0", PLUGIN_IDENTIFIER));
            if (response.responseCode() != 200) {
                LOGGER.warn("Unable to fetch GoCD server info (response code " + response.responseCode() + "); proceeding without a server id.");
                return null;
            }
            return ServerInfo.fromJSON(response.responseBody()).getServerId();
        } catch (Exception e) {
            LOGGER.warn("Unable to fetch GoCD server info; proceeding without a server id.", e);
            return null;
        }
    }

    @Override
    public GoPluginApiResponse handle(GoPluginApiRequest request) throws UnhandledRequestTypeException {
        return requestDispatcher.dispatch(request);
    }

    @Override
    public GoPluginIdentifier pluginIdentifier() {
        return PLUGIN_IDENTIFIER;
    }
}
