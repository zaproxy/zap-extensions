import org.zaproxy.gradle.addon.AddOnStatus

description = "Show hidden fields and enable disabled fields"

zapAddOn {
    addOnName.set("Reveal")
    addOnStatus.set(AddOnStatus.RELEASE)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/reveal/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.reveal.RevealAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/reveal/resources/Messages.properties"))
    }
}
