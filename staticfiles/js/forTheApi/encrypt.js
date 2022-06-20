// Encrypt a text
const plainText = document.getElementById('plaintext');
const publicKey = document.getElementById('publicKey');
const cyphertext = document.getElementById('encrypted-text');
const encryptTextButton = document.getElementById('encryptTextButton');

// Hide encrypted text into image
const f5keys = document.getElementsByClassName('f5keys');
const email = document.getElementById('email');
const cyphertextToHide = document.getElementById('ciphertext-to-hide');
const image = document.getElementById('image');
const hideAndSendButton = document.getElementById('hideImageAndSend');
const showStatus = document.getElementById('showStatus');

encryptTextButton.addEventListener('click', async function(e) {
    e.preventDefault();

    console.log(localStorage.getItem('token'));
    const res = await fetch(baseUrl + 'encrypt-text', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            token: localStorage.getItem('token')
        },
        body: JSON.stringify({
            text: plainText.value,
            encryptionKey: publicKey.value
        })
    });

    const response = await res.json();
    console.log(response);
    if(response.ciphertext) {
        cyphertext.innerText = response.ciphertext;
    }
});


hideAndSendButton.addEventListener('click', async function(e) {
    e.preventDefault();
    hideAndSendButton.innerText = "Sending...";
    let keysArr = [];
    for(let i = 0; i < f5keys.length; i++) {
        keysArr.push(f5keys[i].value);
    }
    
    const neededKey = keysArr.join(',');

    let formdata = new FormData();

      formdata.append('file', image.files[0]);


    const res = await fetch(baseUrl + 'hide-text-in-image', {
        method: 'POST',
        headers: {
            token: localStorage.getItem('token'),
            f5key: neededKey,
            textToHide: cyphertextToHide.value,
            email: email.value
        },
        body: formdata
    });

    const response = await res.json();

    if(response.status) {
        hideAndSendButton.innerText = "Hide cyphertext in image and send";
        showStatus.innerText = "Successful";
    } else {
        hideAndSendButton.innerText = "Hide cyphertext in image and send";
        showStatus.innerText = "An error has occured";
    }
});

/* '-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAJXX2rrqNHRxwxdO3Uauih1HgTcXq6F3xr/SpDmgPyWnik5sLU+BWUke
f9DPMm3+dKY7UDdJO8JSexYYLv98vaJvFKJqSDoOzpscF2nlCpc2SW1xv2ZwpGTm
VBw/QEKwCMGXOZi0FaxeD7t5DDYwoXSZy+SLmvEhjt8UNp7Hh6uBAgMBAAE=
-----END RSA PUBLIC KEY-----' */

/*
Encrypted text

HbdhSvQQLpqMivsY0LTcHNrGGX-eGtRfAhV8VnjcnMQJ8TpuCPA870jxLukYEvI5ghUotr4wyEaonNVwhpHyzCGVKpOz6unr6r6-X9gxPQulssdXt_0LEGDEQZ74WQ-kaXE3uvtgcU-RdbTBZ-Jl055AiuTHKc2r-JvDgqEEx3o=
*/