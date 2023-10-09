let objectToInspect = window, result = [];
while (objectToInspect !== null) {
    result = result.concat(Object.getOwnPropertyNames(objectToInspect));
    objectToInspect = Object.getPrototypeOf(objectToInspect);
}
result.forEach(p => p.match(/^cdc_[a-zA-Z0-9_]{20,}/ig)
    && delete window[p])
