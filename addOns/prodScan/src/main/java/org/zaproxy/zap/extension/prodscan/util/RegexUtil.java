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
package org.zaproxy.zap.extension.prodscan.util;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.network.HttpResponseBody;

public abstract class RegexUtil {

    public static Optional<String> find(HttpMessage msg, String regex) {
        final HttpResponseHeader header = msg.getResponseHeader();
        if (header.isText()) {
            final HttpResponseBody body = msg.getResponseBody();
            Matcher m = Pattern.compile(regex).matcher(body.toString());
            if (m.find()) {
                return Optional.ofNullable(m.group());
            }
        }
        return Optional.empty();
    }
}
