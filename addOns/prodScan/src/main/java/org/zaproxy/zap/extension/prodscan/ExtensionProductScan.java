package org.zaproxy.zap.extension.prodscan;

import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

public class ExtensionProductScan extends ExtensionAdaptor {

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        super.hook(extensionHook);
    }

}
