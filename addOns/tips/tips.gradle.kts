import org.zaproxy.gradle.addon.AddOnStatus

description = "Display ZAP Tips and Tricks"

zapAddOn {
    addOnName.set("Tips and Tricks")
    addOnStatus.set(AddOnStatus.BETA)

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/tips-and-tricks/")
    }
}
