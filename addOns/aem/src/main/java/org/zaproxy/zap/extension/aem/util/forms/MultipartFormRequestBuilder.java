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
package org.zaproxy.zap.extension.aem.util.forms;

import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.parosproxy.paros.core.scanner.NameValuePair;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;

public class MultipartFormRequestBuilder {
    private final HttpMessage message;

    private final String boundary;

    private final List<NameValuePair> params = new ArrayList<>();

    private MultipartFormRequestBuilder(HttpMessage message) {
        this.message = message.cloneRequest();
        boundary = getNewBoundry(16);
    }

    public MultipartFormRequestBuilder param(String key, String value) {
        params.add(new NameValuePair(NameValuePair.TYPE_MULTIPART_DATA_PARAM, key, value, 0));
        return this;
    }

    /** https://www.ietf.org/rfc/rfc2388.txt */
    public HttpMessage build() {
        HttpRequestHeader header = message.getRequestHeader();
        header.setHeader(
                HttpHeader.CONTENT_TYPE,
                MessageFormat.format("multipart/form-data; boundary={0}", boundary));
        header.setMethod("POST");

        StringBuilder body = new StringBuilder();

        for (NameValuePair param : params) {
            body.append(boundary);
            body.append(HttpHeader.CRLF);
            if (param.getType() == NameValuePair.TYPE_MULTIPART_DATA_PARAM) {
                body.append("Content-Disposition: form-data; name=\"");
                body.append(param.getName());
                body.append("\"");
                body.append(HttpHeader.CRLF);
                body.append(HttpHeader.CRLF);
                body.append(param.getValue());
                body.append(HttpHeader.CRLF);
            }
        }
        body.append(boundary);
        body.append("--");

        message.setRequestBody(body.toString());
        return message;
    }

    public static MultipartFormRequestBuilder builder(HttpMessage message) {
        return new MultipartFormRequestBuilder(message);
    }

    private String getNewBoundry(int numchars) {
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        sb.append("------------------------");
        numchars += sb.length();
        while (sb.length() < numchars) {
            sb.append(Integer.toHexString(random.nextInt()));
        }
        return sb.toString().substring(0, numchars);
    }
}
