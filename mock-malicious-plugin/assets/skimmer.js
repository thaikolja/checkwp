const payload  = 'YWxlcnQoJ3NraW1tZXInKTs='
const checkout = document.getElementById('checkout')
if (checkout) {
  checkout.innerHTML = window.location.hash.slice(1)
}

eval(atob(payload))
const hidden = String.fromCharCode(97, 108, 101, 114, 116, 40, 49, 41)

