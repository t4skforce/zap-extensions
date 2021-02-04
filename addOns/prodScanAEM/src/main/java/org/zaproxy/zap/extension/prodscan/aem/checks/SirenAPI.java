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
import java.util.Optional;
import java.util.function.Function;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.prodscan.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.prodscan.util.HistoryUtil;
import org.zaproxy.zap.extension.prodscan.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.extension.prodscan.util.JsonUtil;

public class SirenAPI extends AbstractHostScan {

    private static final String MESSAGE_PREFIX = "aem.api.siren";

    private static final List<String> PATHS = Arrays.asList("/api.json", "/api/assets.json", "/api/content.json",
            "/api/screens.json", "/api/screens-dcc.json");

    public static final int ID = 5002;

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
                .map(path -> HttpMessageWrapperUtil.get(baseMessage, path).orElse(null))
                .filter(Objects::nonNull)
                .map(origin -> fuzzDispatcher(origin))
                .flatMap(Function.identity())
                .filter(sendAndReceive(msg -> {
                    if (isSuccess(msg)) {
                        Optional<String> json = JsonUtil.string(msg, ".links[0].href");
                        json.ifPresent(evidence -> msg.setNote(evidence));
                        return json.isPresent();
                    } else if (isServerError(msg)) {
                        // this could be interesting for passive rules
                        HistoryUtil.addForPassiveScan(msg, "AEM", "Error");
                    }
                    return false;
                }, false))
                .findFirst()
                .ifPresent(msg -> {
                    newAlert().setEvidence(msg.getNote()).setMessage(msg).raise();
                });
    }

}
