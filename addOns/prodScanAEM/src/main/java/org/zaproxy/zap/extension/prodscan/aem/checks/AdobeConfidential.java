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

import java.io.IOException;
import java.nio.file.Paths;
import java.util.List;
import java.util.Objects;

import org.apache.commons.collections4.ListUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.prodscan.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.prodscan.util.HistoryUtil;
import org.zaproxy.zap.extension.prodscan.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.network.HttpResponseBody;

public class AdobeConfidential extends AbstractHostScan {
    private static final String JCR_REPOSITORY = "JCR repository";

    private static final String ADOBE_CONFIDENTIAL = "ADOBE CONFIDENTIAL";

    private static final String MESSAGE_PREFIX = "prodScanAEM.static.files";

    public static final int ID = 5001;

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
    public int getRisk() {
        return Alert.RISK_INFO;
    }

    @Override
    public String getMessagePrefix() {
        return MESSAGE_PREFIX;
    }

    private List<String> getPaths() throws IOException {
        AttackStrength strength = getAttackStrength();
        List<String> paths = FileUtils
                .readLines(Paths.get(Constant.getZapHome(), "aem").resolve("adobeConfidential.txt").toFile(), "UTF-8");

        if (AttackStrength.LOW.equals(strength)) {
            paths = ListUtils.partition(paths, 36).get(0);
        } else if (AttackStrength.MEDIUM.equals(strength)) {
            paths = ListUtils.partition(paths, 72).get(0);
        } else if (AttackStrength.HIGH.equals(strength)) {
            paths = ListUtils.partition(paths, 288).get(0);
        }

        return paths;
    }

    @Override
    public void doScan(HttpMessage baseMessage) throws Exception {

        getPaths().stream()
                .map(path -> HttpMessageWrapperUtil.get(getBaseMsg(), path).orElse(null))
                .filter(Objects::nonNull)
                .filter(sendAndReceive(msg -> {
                    HttpResponseHeader header = msg.getResponseHeader();
                    if (isSuccess(msg) && header.isText()) {
                        // this could be interesting for passive rules
                        HistoryUtil.addForPassiveScan(msg, "AEM");
                        HttpResponseBody body = msg.getResponseBody();
                        String bodyStr = body.toString();
                        if (StringUtils.containsIgnoreCase(bodyStr, ADOBE_CONFIDENTIAL)) {
                            msg.setNote(ADOBE_CONFIDENTIAL);
                            return true;
                        } else if (StringUtils.containsIgnoreCase(bodyStr, JCR_REPOSITORY)) {
                            msg.setNote(JCR_REPOSITORY);
                            return true;
                        }
                    } else if (isServerError(msg)) {
                        // this could be interesting for passive rules
                        HistoryUtil.addForPassiveScan(msg, "AEM", "Error");
                    }
                    return false;
                }, false))
                .forEach(msg -> {
                    newAlert().setEvidence(msg.getNote()).setMessage(msg).setRisk(Alert.RISK_INFO).raise();
                });
    }

}
