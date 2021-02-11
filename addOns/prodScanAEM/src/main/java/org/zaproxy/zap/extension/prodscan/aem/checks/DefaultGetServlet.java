/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2020 The ZAP Development Team
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
package org.zaproxy.zap.extension.prodscan.aem.checks;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.prodscan.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.prodscan.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.extension.prodscan.util.fuzzer.HttpRequestFuzzBuilder;

public class DefaultGetServlet extends AbstractHostScan {

    public static final int ID = 5004;
    private static final String MESSAGE_PREFIX = "prodScanAEM.get.servlet";
    private static final List<String> PATHS = Arrays.asList("/", "/etc", "/var", "/apps", "/home");

    @Override
    public int getId() {
        return ID;
    }

    @Override
    public int getCweId() {
        // CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
        // http://cwe.mitre.org/data/definitions/200.html
        return 200;
    }

    @Override
    public int getWascId() {
        return 1;
    }

    @Override
    public int getCategory() {
        return Category.INFO_GATHER;
    }

    @Override
    public String getMessagePrefix() {
        return MESSAGE_PREFIX;
    }

    @Override
    public int getRisk() {
        return Alert.RISK_MEDIUM;
    }

    @Override
    public void doScan(HttpMessage baseMessage) throws Exception {
        PATHS.stream()
                .map(path -> HttpMessageWrapperUtil.get(getBaseMsg(), path).orElse(null))
                .filter(Objects::nonNull)
                .map(origin -> HttpRequestFuzzBuilder.builder(origin)
                        .setFileExtension(".children")
                        .setFileExtension(".json")
                        .stream())
                .flatMap(Function.identity())
                .map(origin -> fuzzDispatcher(origin))
                .flatMap(Function.identity())
                .filter(sendAndReceive(msg -> {
                    return isSuccess(msg) || isClientError(msg);
                }, false))
                .findFirst()
                .ifPresent(msg -> {

                });
    }

}
