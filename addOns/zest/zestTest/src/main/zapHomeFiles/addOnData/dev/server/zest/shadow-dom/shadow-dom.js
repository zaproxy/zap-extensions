/*
 * Creates the shadow roots of a case, with the link, the button and the form in the innermost one.
 *
 * The config has the modes of the shadow roots, outermost first, and the delay (in milliseconds)
 * before each host (and its shadow root) is created, 0 to create them immediately.
 * The hosts have the IDs host0, host1, ... and no references to the shadow roots are kept, which
 * makes the closed ones inaccessible from the page.
 */
function createShadowDom(config) {
  function later(fn) {
    if (config.delay > 0) {
      setTimeout(fn, config.delay);
    } else {
      fn();
    }
  }

  function addContent(root) {
    root.innerHTML = `
      <p>Shadow root(s): ${config.modes.join(" > ")}</p>
      <p><a id="link" href="link">Link</a></p>
      <p><button id="button" type="button">Button</button></p>
      <form id="form" action="form" method="get">
        <input id="input" name="value" type="text">
        <button id="submit" type="submit">Submit</button>
      </form>`;
    root.getElementById("button").addEventListener("click", () => {
      location.href = "button";
    });
  }

  function attach(parent, level) {
    const host = document.createElement("div");
    host.id = "host" + level;
    parent.appendChild(host);
    const root = host.attachShadow({ mode: config.modes[level] });
    if (level + 1 < config.modes.length) {
      later(() => attach(root, level + 1));
    } else {
      addContent(root);
    }
  }

  later(() => attach(document.getElementById("container"), 0));
}
