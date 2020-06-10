package org.zaproxy.zap.extension.aem.checks;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.network.HttpResponseHeader;
import org.zaproxy.zap.extension.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.aem.util.HistoryUtil;
import org.zaproxy.zap.extension.aem.util.HttpMessageWrapperUtil;
import org.zaproxy.zap.extension.aem.util.JsonUtil;

public class SirenAPI extends AbstractHostScan {

	private static final String MESSAGE_PREFIX = "aem.api.siren";

	private static final List<String> PATHS = Arrays.asList("/api.json", "/api/content.json", "/api/screens.json");

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
					HttpResponseHeader header = msg.getResponseHeader();
					int statusCode = header.getStatusCode();
					if (statusCode == 200) {
						Optional<String> json = JsonUtil.query(msg, ".links[0].href");
						json.ifPresent(evidence -> msg.setNote(evidence));
						return json.isPresent();
					} else if (statusCode >= 500) {
						// this could be interesting for passive rules
						HistoryUtil.addForPassiveScan(msg, "error");
					}
					return false;
				}, false))
				.findFirst()
				.ifPresent(msg -> {
					newAlert().setEvidence(msg.getNote()).setMessage(msg).raise();
				});
	}

}
