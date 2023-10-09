import org.zaproxy.gradle.addon.AddOnStatus

description = "Ability to add, edit or remove payloads that are used i.e. by active scanners"

zapAddOn {
    addOnName.set("Custom Payloads")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/custom-payloads/")
    }
}
