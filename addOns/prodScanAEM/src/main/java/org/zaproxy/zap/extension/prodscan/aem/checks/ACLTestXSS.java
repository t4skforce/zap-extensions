package org.zaproxy.zap.extension.prodscan.aem.checks;

import java.text.MessageFormat;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;
import java.util.function.Function;

import org.apache.commons.lang3.StringUtils;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.prodscan.aem.base.AbstractHostScan;
import org.zaproxy.zap.extension.prodscan.util.HistoryUtil;
import org.zaproxy.zap.extension.prodscan.util.HttpMessageWrapperUtil;

/*
 * TODO: implement fuzzing
 *
 * Affects all servlets that use ServletResolverConstants.SLING_SERVLET_PATHS or @SlingServletPaths. Basically everybody can access any of those servlets even without authentication
 * https://<domain>/<single-element-that-does-not-get-rewritten-by-dispatcher-internally>/..;<your-servlet-plus-any-allowed-extension>
 *
 * this also affects the crx development bundle, so if you have those enabled you can do something like
 * https://<domain>/content/..;/crx/explorer/ui/acltest.jsp?Path=/&testPri[…]ons=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
 * https://<domain>/etc.clientlibs/..;/crx/explorer/ui/acltest.jsp?Path=/[…]ons=%3Cimg%20src=x%20onerror=alert(document.cookie)%3E
 * https://<domain>/etc.clientlibs/..;/crx/de/index.jsp
 * */
public class ACLTestXSS extends AbstractHostScan {

    public static final int ID = 5005;

    private static final String MESSAGE_PREFIX = "prodScanAEM.acltest.xss";

    private static final Set<String> ATTACKS = new TreeSet<>(Arrays.asList(
            "/content/..;/crx/explorer/ui/acltest.jsp?Path=/&testPrincipal=&actions=<img src=x onerror=alert(''{0}'')>"));

    private static final String EVIDENCE = "<img src=x onerror=alert(''{0}'')>";

    @Override
    public int getId() {
        return ID;
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
        return Alert.RISK_HIGH;
    }

    @Override
    public void doScan(HttpMessage baseMessage) throws Exception {
        String seed = UUID.randomUUID().toString();
        ATTACKS.stream()
                .map(path -> MessageFormat.format(path, seed))
                .map(path -> HttpMessageWrapperUtil.get(getBaseMsg(), path).orElse(null))
                .filter(Objects::nonNull)
                .map(origin -> fuzzDispatcher(origin)) // TODO: set query param -> makes nonsense
                .flatMap(Function.identity())
                .filter(sendAndReceive(msg -> {
                    String evidence = MessageFormat.format(EVIDENCE, seed);
                    if (isSuccess(msg) && StringUtils.containsIgnoreCase(msg.getResponseBody().toString(), evidence)) {
                        msg.setNote(evidence);
                        return true;
                    } else if (isServerError(msg)) {
                        HistoryUtil.addForPassiveScan(msg, "AEM", "Error");
                    }
                    return false;
                }, false))
                .findFirst()
                .ifPresent(msg -> {
                    newAlert().setEvidence(msg.getNote())
                            .setMessage(msg)
                            .setRisk(Alert.RISK_HIGH)
                            .setOtherInfo(getOtherInfo())
                            .raise();
                });
    }

}
