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
package org.zaproxy.zap.extension.aem.checks;

import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Stream;

import org.apache.commons.httpclient.UsernamePasswordCredentials;
import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.aem.exploit.BasicAuthLoginSupported;
import org.zaproxy.zap.extension.aem.util.HistoryUtil;
import org.zaproxy.zap.extension.aem.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.extension.aem.util.RegexUtil;
import org.zaproxy.zap.network.HttpResponseBody;

public class LoginStatusServlet extends AbstractHostScan implements BasicAuthLoginSupported {

	private static final String RE_AUTHENTICATED_TRUE_FALSE = "(?i)authenticated=(true|false)";

	private static final String SYSTEM_SLING_LOGINSTATUS = "/system/sling/loginstatus";

	private static final String MESSAGE_PREFIX = "aem.loginstatus";

	private static final String USERID = "userid=";

	private static final String AUTHENTICATED_TRUE = "authenticated=true";

	public static final int ID = 5000;

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
		return Category.SERVER;
	}

	@Override
	public String getMessagePrefix() {
		return MESSAGE_PREFIX;
	}

	@Override
	public int getRisk() {
		return Alert.RISK_HIGH;
	}

	@Override
	public void doScan(HttpMessage baseMessage) throws Exception {
		HttpMessageWrapperUtil.get(baseMessage, SYSTEM_SLING_LOGINSTATUS).ifPresent(requestMessage -> {
			Stream.of(requestMessage)
					.map(origin -> fuzzDispatcher(origin))
					.flatMap(Function.identity())
					.filter(sendAndReceive(msg -> {
						HttpResponseHeader header = msg.getResponseHeader();
						int statusCode = header.getStatusCode();
						if (header.getStatusCode() == 200) {
							Optional<String> auth = RegexUtil.find(msg, RE_AUTHENTICATED_TRUE_FALSE);
							msg.setNote(auth.orElse(StringUtils.EMPTY));
							return auth.isPresent();
						} else if (statusCode >= 500) {
							// this could be interesting for passive
							// rules
							HistoryUtil.addForPassiveScan(msg, "error");
						}
						return false;
					}, false))
					.findFirst()
					.ifPresent(msg -> {
						// raise alter
						newAlert().setEvidence(msg.getNote()).setMessage(msg).setRisk(Alert.RISK_MEDIUM).raise();
					});
		});
	}

	@Override
	public Optional<String> getLoginSuccessEvidence(HttpMessage msg, UsernamePasswordCredentials user) {
		return Optional.ofNullable(msg)
				.filter(m -> m.getResponseHeader().getStatusCode() == 200 && m.getResponseHeader().isText())
				.map(m -> m.getResponseBody())
				.filter(Objects::nonNull)
				.map(HttpResponseBody::toString)
				.filter(StringUtils::isNoneBlank)
				.map(content -> {
					if (Objects.nonNull(user) && StringUtils.contains(content, USERID + user.getUserName())) {
						return user.getUserName();
					} else if (StringUtils.contains(content, AUTHENTICATED_TRUE)) {
						return AUTHENTICATED_TRUE;
					}
					return null;
				})
				.filter(Objects::nonNull);
	}
}
