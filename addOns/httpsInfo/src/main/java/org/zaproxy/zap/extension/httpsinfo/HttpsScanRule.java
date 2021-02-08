package org.zaproxy.zap.extension.httpsinfo;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.httpclient.URI;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.core.scanner.AbstractHostPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;

import com.mps.deepviolet.api.DVException;
import com.mps.deepviolet.api.DVFactory;
import com.mps.deepviolet.api.IDVCipherSuite;
import com.mps.deepviolet.api.IDVEng;
import com.mps.deepviolet.api.IDVSession;

public class HttpsScanRule extends AbstractHostPlugin {

    private static final Logger LOG = Logger.getLogger(HttpsScanRule.class);

    private static final String MESSAGE_PREFIX = "httpsinfo.scan.";

    @Override
    public int getId() {
        return 90012;
    }

    @Override
    public String getName() {
        return Constant.messages.getString(MESSAGE_PREFIX + "name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString(MESSAGE_PREFIX + "description");
    }

    @Override
    public void scan() {
        /*
         * com.mps.deepviolet.api.CipherSuiteUtil.initCipherMap() loads json
         */
        HttpMessage baseMsg = getBaseMsg();
        URI origin = baseMsg.getRequestHeader().getURI();
        if ("https".equalsIgnoreCase(origin.getScheme())) {
            IDVSession session;
            try {
                session = DVFactory.initializeSession(new URL(origin.toString()));
            } catch (DVException | MalformedURLException e) {
                String warnMsg = Constant.messages.getString("httpsinfo.init.warning", origin.toString(), e.getCause());
                LOG.warn(warnMsg);
                return;
            }

            IDVEng iDVEng;
            try {
                iDVEng = DVFactory.getDVEng(session);
            } catch (DVException e) {
                LOG.warn(e.getMessage(), e);
                return;
            }

            IDVCipherSuite[] ciphers = null;
            try {
                ciphers = iDVEng.getCipherSuites();
            } catch (DVException e) {
                String cipherSuitesException = Constant.messages.getString("httpsinfo.ciphersuites.exception",
                        e.getMessage());
                LOG.warn(cipherSuitesException, e);
                return;
            }
            Set<IDVCipherSuite> css = new HashSet<>();

            for (IDVCipherSuite cipher : ciphers) {
                // If cipher's in the set then skip
                if (!css.contains(cipher)) {
                    StringBuilder cs = new StringBuilder();
                    cs.append(cipher.getSuiteName());
                    cs.append('(');
                    cs.append(cipher.getStrengthEvaluation());
                    cs.append(',');
                    cs.append(cipher.getHandshakeProtocol());
                    cs.append(')');
                    LOG.info(cs.toString());
                    css.add(cipher);
                }
            }
        }
    }

    @Override
    public int getCategory() {
        return Category.SERVER;
    }

    @Override
    public String getSolution() {
        return Constant.messages.getString(MESSAGE_PREFIX + "solution");
    }

    @Override
    public String getReference() {
        return StringUtils.EMPTY;
    }

}
