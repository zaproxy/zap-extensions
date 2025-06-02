description = "Provides a tab which allows you to view the list of test cases"

zapAddOn {
    addOnName.set("ToDo-List")

    manifest {
        author.set("vishesh, ZAP Dev Team")
        url.set("https://www.zaproxy.org/docs/desktop/addons/todo-list/")

        helpSet {
            baseName.set("help%LC%.helpset")
            localeToken.set("%LC%")
        }
    }
}

crowdin {
    configuration {
        tokens.put("%helpPath%", "")
    }
}
