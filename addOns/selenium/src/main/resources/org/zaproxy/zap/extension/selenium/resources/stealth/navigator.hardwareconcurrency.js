// "4" is an arbitrary value. Using a random value may help evade detection.
utils.replaceGetterWithProxy(
    Object.getPrototypeOf(navigator),
    'hardwareConcurrency',
    utils.makeHandler().getterValue(4)
)
