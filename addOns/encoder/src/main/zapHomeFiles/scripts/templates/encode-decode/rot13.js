// This ROT13 example only handles upper and lower case A to Z (no numbers, punctuation, or extended chars)
function process(helper, value){
  return helper.newResult(rot13(value));
}

function rot(chr, start, val) {
  return String.fromCharCode(((chr-start+val)%(val*2))+start);
}

function rot13(inStr) {
  var outArray = [], chr, idx = inStr.length,
  a = 'a'.charCodeAt(), z = a + 26,
  A = 'A'.charCodeAt(), Z = A + 26;
  while(idx--) {
    chr = inStr.charCodeAt(idx);
    if (chr>=a && chr<z) { 
      outArray[idx] = rot(chr, a, 13); 
    } else if (chr>=A && chr<Z) { 
      outArray[idx] = rot(chr, A, 13);
    } else { 
      outArray[idx] = inStr.charAt(idx); 
    }
  }
  return outArray.join('');
}
