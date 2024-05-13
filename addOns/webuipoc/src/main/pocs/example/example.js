
async function callApi(url) {
  console.log(`Call: ${url}`);
  const request = new Request(url);
  const response = await fetch(request);
  const ret = await response.json();
  console.log(`Response: ${JSON.stringify(ret)}`);
  return ret;
}

function createHrefLink(href, name) {
  var a = document.createElement('a');
  var linkText = document.createTextNode(name);
  a.appendChild(linkText);
  a.title = name;
  a.href = "reqresp.html?href=" + href;
  a.setAttribute('target', 'reqresp');
  return a;
}

function addChildren(parent, children) {
  var ul = document.createElement('ul');
  ul.setAttribute('class', 'active');
  children.forEach(function(child) {
    var li = document.createElement('li');
    li.setAttribute('data-uri', child.uri);
    var newChild;
    var childName = child.uri;
    var parentUri = parent.getAttribute('data-uri');
    if (parentUri) {
      childName = childName.substring(parentUri.length + 1);
    }
    if (child.isLeaf) {
      newChild = createHrefLink(child.hrefId, childName);
      li.appendChild(newChild);
    } else {
      newChild = document.createElement('span');
      newChild.setAttribute('class', 'caret');
      addClickHandler(newChild, child.uri);
      li.appendChild(newChild);
      li.appendChild(createHrefLink(child.hrefId, childName));
    }
    ul.appendChild(li);
  });
  parent.appendChild(ul);
}

async function addClickHandler(node, url) {
  node.addEventListener("click", async (e) => {
    if (e.target.classList.contains('caret-down')) {
      e.target.classList.toggle("caret-down");
      var toDelete = e.target.parentNode.getElementsByTagName('ul');
      if (toDelete.length > 0) {
        // Just need to remove the first ol - the remainder will be below that
        toDelete[0].remove();
      }
      return;
    }
    var children = await callApi('/JSON/core/view/childNodes/?url=' + url);
    addChildren(e.target.parentNode, children.childNodes);
    e.target.classList.toggle("caret-down");
  });
}

function preWrapper(txt) {
  var pre = document.createElement('pre');
  pre.textContent = txt;
  return pre;
}

async function displayMessage(href) {
  var msg = await callApi('/JSON/core/view/message/?id=' + href);
  document.getElementById('req-head').appendChild(preWrapper(msg.message.requestHeader));
  document.getElementById('req-body').appendChild(preWrapper(msg.message.requestBody));
  document.getElementById('resp-head').appendChild(preWrapper(msg.message.responseHeader));
  document.getElementById('resp-body').appendChild(preWrapper(msg.message.responseBody));
}

