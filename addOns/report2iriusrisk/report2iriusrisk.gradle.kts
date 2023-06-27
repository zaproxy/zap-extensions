version = "0.0.1"
description = "A new description."

zapAddOn {
    addOnName.set("My AddOn")
    zapVersion.set("2.10.0")

    manifest {
        author.set("Álvaro Vázquez Ortiz")
    }
}

crowdin {
    configuration {
        val resourcesPath = "org/zaproxy/addon/${zapAddOn.addOnId.get()}/resources/"
        tokens.put("%messagesPath%", resourcesPath)
        tokens.put("%helpPath%", resourcesPath)
    }
}
