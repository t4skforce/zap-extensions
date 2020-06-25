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
package org.zaproxy.zap.extension.aem.util;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import org.apache.commons.httpclient.URI;
import org.apache.log4j.Logger;
import org.parosproxy.paros.network.HttpHeader;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpRequestHeader;
import org.zaproxy.zap.extension.aem.util.wrapper.HttpMessageWrapper;

public class HttpMessageWrapperUtil {
    private static final Logger LOG = Logger.getLogger(HttpMessageWrapperUtil.class);

    public static Optional<HttpMessageWrapper> post(HttpMessage baseMassege) {
        return request(baseMassege, null, null, null, HttpRequestHeader.POST, true);
    }

    public static Optional<HttpMessageWrapper> post(HttpMessage baseMassege, String path) {
        return request(baseMassege, path, null, null, HttpRequestHeader.POST, true);
    }

    public static Optional<HttpMessageWrapper> post(
            HttpMessage baseMassege, String path, String query) {
        return request(baseMassege, path, query, null, HttpRequestHeader.POST, true);
    }

    public static Optional<HttpMessageWrapper> post(
            HttpMessage baseMassege, String path, String query, String fragment) {
        return request(baseMassege, path, query, fragment, HttpRequestHeader.POST, true);
    }

    public static Optional<HttpMessageWrapper> post(
            HttpMessage baseMassege, String path, String query, String fragment, boolean referer) {
        return request(baseMassege, path, query, fragment, HttpRequestHeader.POST, referer);
    }

    public static Optional<HttpMessageWrapper> get(HttpMessage baseMassege) {
        return request(baseMassege, null, null, null, HttpRequestHeader.GET, true);
    }

    public static Optional<HttpMessageWrapper> get(HttpMessage baseMassege, String path) {
        return request(baseMassege, path, null, null, HttpRequestHeader.GET, true);
    }

    public static Optional<HttpMessageWrapper> get(
            HttpMessage baseMassege, String path, String query) {
        return request(baseMassege, path, query, null, HttpRequestHeader.GET, true);
    }

    public static Optional<HttpMessageWrapper> get(
            HttpMessage baseMassege, String path, String query, String fragment) {
        return request(baseMassege, path, query, fragment, HttpRequestHeader.GET, true);
    }

    public static Optional<HttpMessageWrapper> get(
            HttpMessage baseMassege, String path, String query, String fragment, boolean referer) {
        return request(baseMassege, path, query, fragment, HttpRequestHeader.GET, referer);
    }

    public static Optional<HttpMessageWrapper> request(
            HttpMessage baseMassege,
            String path,
            String query,
            String fragment,
            String method,
            boolean referer) {
        return Optional.ofNullable(baseMassege)
                .map(
                        bm -> {
                            URI origin = baseMassege.getRequestHeader().getURI();
                            try {
                                final String scheme = origin.getScheme();
                                final String authority = origin.getAuthority();
                                URI target = new URI(scheme, authority, path, query, fragment);

                                HttpRequestHeader reqestHeader =
                                        new HttpRequestHeader(method, target, HttpHeader.HTTP11);
                                reqestHeader.addHeader(
                                        "Referer",
                                        new URI(
                                                        origin.getScheme(),
                                                        origin.getAuthority(),
                                                        null,
                                                        null,
                                                        null)
                                                .toString());

                                return new HttpMessageWrapper(reqestHeader);
                            } catch (IOException e) {
                                LOG.error(e.getMessage(), e);
                            }
                            return null;
                        })
                .filter(Objects::nonNull);
    }
}
