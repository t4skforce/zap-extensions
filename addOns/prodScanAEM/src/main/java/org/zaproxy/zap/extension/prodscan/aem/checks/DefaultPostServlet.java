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

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.prodscan.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.prodscan.util.HTMLUtil;
import org.zaproxy.zap.extension.prodscan.util.HistoryUtil;
import org.zaproxy.zap.extension.prodscan.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.extension.prodscan.util.form.MultipartFormRequestBuilder;

public class DefaultPostServlet extends AbstractHostScan {

    private static final String PERSISTANCE_EXCEPTION = "org.apache.sling.api.resource.PersistenceException";

    private static final String SLING_EXCEPTION = "org.apache.sling.api.SlingException";

    private static final String MESSAGE_PREFIX = "prodScanAEM.post.servlet";

    private static final String CVE_PREFIX = "prodScanAEM.post.servlet.cve";

    private static final List<String> PATHS = Arrays.asList("/", "/content", "/content/dam");

    public static final int ID = 5003;

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
        return Category.INJECTION;
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
                .map(path -> HttpMessageWrapperUtil.post(getBaseMsg(), path).orElse(null))
                .filter(Objects::nonNull)
                .map(origin -> MultipartFormRequestBuilder.builder(origin)
                        .param(":operation", "delete")
                        .param(":applyTo", "/etc/*")
                        .build())
                .map(origin -> fuzzDispatcher(origin))
                .flatMap(Function.identity())
                .filter(sendAndReceive(msg -> {
                    if (isServerError(msg)) {
                        Optional<String> json = HTMLUtil.html(msg, "#Message:contains(" + PERSISTANCE_EXCEPTION
                                + "),#Message:contains(" + SLING_EXCEPTION + ")");
                        json.ifPresent(evidence -> msg.setNote(evidence));
                        HistoryUtil.addForPassiveScan(msg, "AEM", "Error");
                        return true;
                    }
                    return false;
                }, false))
                .findFirst()
                .ifPresent(msg -> {
                    String note = msg.getNote();
                    if (StringUtils.contains(note, PERSISTANCE_EXCEPTION)) {
                        // unpatched CVE-2016-0956
                        newAlert().setName(Constant.messages.getString(CVE_PREFIX + ".name"))
                                .setDescription(Constant.messages.getString(CVE_PREFIX + ".description"))
                                .setSolution(Constant.messages.getString(CVE_PREFIX + ".solution"))
                                .setReference(Constant.messages.getString(CVE_PREFIX + ".reference"))
                                .setEvidence(msg.getNote())
                                .setMessage(msg)
                                .setRisk(Alert.RISK_HIGH)
                                .raise();
                    } else if (StringUtils.contains(note, SLING_EXCEPTION)) {
                        // patched CVE-2016-0956
                        newAlert().setEvidence(msg.getNote()).setMessage(msg).setRisk(Alert.RISK_MEDIUM).raise();
                    } else {
                        // patched and no default error page, but we have a 500 error code
                        newAlert().setEvidence(msg.getResponseHeader().getPrimeHeader())
                                .setMessage(msg)
                                .setRisk(Alert.RISK_LOW)
                                .raise();
                    }
                });
    }
}
