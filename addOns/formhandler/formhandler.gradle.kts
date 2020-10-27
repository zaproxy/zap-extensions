import org.zaproxy.gradle.addon.AddOnStatus

version = "3"
description = "This Form Handler Add-on allows a user to define field names and values to be used in a form's fields. Fields can be added, modified, enabled, and deleted for use in form fields."

zapAddOn {
    addOnName.set("Form Handler")
    addOnStatus.set(AddOnStatus.BETA)
    zapVersion.set("2.9.0")

    manifest {
        author.set("ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/form-handler/")
    }
}
