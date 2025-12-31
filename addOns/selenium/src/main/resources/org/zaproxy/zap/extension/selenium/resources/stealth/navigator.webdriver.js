if (navigator.webdriver === false) {
    // Post Chrome 89.0.4339.0 and already good
} else if (navigator.webdriver === undefined) {
    // Pre Chrome 89.0.4339.0 and already good
} else {
    // Post Chrome 89.0.4339.0 and needs patching
    utils.replaceGetterWithProxy(
        Object.getPrototypeOf(navigator),
        'webdriver',
        utils.makeHandler().getterValue(false)
    )
}
