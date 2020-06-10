package org.zaproxy.zap.extension.aem.util;

import java.awt.EventQueue;
import java.util.Arrays;
import java.util.Optional;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.history.ExtensionHistory;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import org.parosproxy.paros.view.View;

public abstract class HistoryUtil {
	private static Logger log = Logger.getLogger(HistoryUtil.class);

	public static final Optional<HistoryReference> addForPassiveScan(HttpMessage msg, String... tags) {
		return add(msg, HistoryReference.TYPE_PROXIED, null, tags);
	}

	public static final Optional<HistoryReference> add(HttpMessage msg, int type, String icon, String... tags) {
		// Add message to history
		try {
			final HistoryReference historyRef = new HistoryReference(Model.getSingleton().getSession(), type, msg);
			if (ArrayUtils.isNotEmpty(tags)) {
				Arrays.asList(tags).forEach(t -> historyRef.addTag(t));
			}
			if (StringUtils.isNoneBlank(icon)) {
				historyRef.setCustomIcon(icon, true);
			}

			if (View.isInitialised()) {
				final ExtensionHistory extHistory = (ExtensionHistory) Control.getSingleton().getExtensionLoader()
						.getExtension(ExtensionHistory.NAME);
				if (extHistory != null) {
					EventQueue.invokeLater(new Runnable() {
						@Override
						public void run() {
							extHistory.addHistory(historyRef);
							Model.getSingleton().getSession().getSiteTree().addPath(historyRef, msg);
						}
					});
				}
			}

			return Optional.of(historyRef);
		} catch (Exception ex) {
			log.error("Cannot add message to History tab.", ex);
		}
		return Optional.empty();
	}

}
