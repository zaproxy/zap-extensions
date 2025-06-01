description = "Revisit a site at any time in the past using the session history"

zapAddOn {
    addOnName.set("Revisit")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/revisit/")
    }

    apiClientGen {
        api.set("org.zaproxy.zap.extension.revisit.RevisitAPI")
        messages.set(file("src/main/resources/org/zaproxy/zap/extension/revisit/resources/Messages.properties"))
    }
}
