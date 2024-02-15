package org.zaproxy.zap.extension.plugnhack.brk;


import java.util.List;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.extension.Extension;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;
import org.zaproxy.addon.brk.ExtensionBreak;
import org.zaproxy.zap.extension.plugnhack.ExtensionPlugNHack;

public class ExtensionPlugNHackBrk extends ExtensionAdaptor {

    private static final List<Class<? extends Extension>> DEPENDENCIES =
            List.of(ExtensionPlugNHack.class, ExtensionBreak.class);

    @Override
    public String getUIName() {
        return Constant.messages.getString("quickstart.spider.name");
    }

    @Override
    public String getDescription() {
        return Constant.messages.getString("quickstart.spider.desc");
    }

    @Override
    public List<Class<? extends Extension>> getDependencies() {
        return DEPENDENCIES;
    }

    @Override
    public void hook(ExtensionHook extensionHook) {
        getExtension(ExtensionPlugNHack.class).setExtensionBreak(getExtension(ExtensionBreak.class));
    }

    private static <T extends Extension> T getExtension(Class<T> clazz) {
        return Control.getSingleton().getExtensionLoader().getExtension(clazz);
    }

    @Override
    public boolean canUnload() {
        return true;
    }

    @Override
    public void unload() {
        getExtension(ExtensionPlugNHack.class).setExtensionBreak(null);
    }
}
