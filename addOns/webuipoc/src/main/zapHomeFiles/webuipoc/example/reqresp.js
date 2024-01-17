
document.addEventListener("DOMContentLoaded", function() {
  const paramsString = window.location.search;
  const searchParams = new URLSearchParams(paramsString);
  var href = searchParams.get('href');

  if (href) {
    displayMessage(href);
  }
});

