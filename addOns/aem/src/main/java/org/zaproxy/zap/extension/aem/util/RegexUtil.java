package org.zaproxy.zap.extension.aem.util;

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
