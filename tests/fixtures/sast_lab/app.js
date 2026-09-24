// Deliberately insecure source fixture, never executed.
function render(user) {
  eval(user);
  new Function(user);
  document.querySelector('#result').innerHTML = user;
  node.outerHTML = user;
  document.write(user);
}
function safe(user) {
  node.textContent = user;
  node.innerHTML = DOMPurify.sanitize(user);
  document.write('Static text');
}
const demonstration = "eval(user)";
