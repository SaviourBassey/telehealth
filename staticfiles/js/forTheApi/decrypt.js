// Seperate text from image
const f5keys = document.getElementsByClassName('stegkey');
const imageFile = document.getElementById('image');
const showCiphertext = document.getElementById('showCiphertext');
const theCyphertext = document.getElementById('theCyphertext');
const seperateImageButton = document.getElementById('seperateImage');

// Decrypt the ciphertext
const ciphertext = document.getElementById('ciphertext');
const privateKey = document.getElementById('privatekey');
const decryptButton = document.getElementById('decryptButton');

seperateImageButton.addEventListener('click', async function(e) {
    e.preventDefault();
    let keysArr = [];
    for(let i = 0; i < f5keys.length; i++) {
        keysArr.push(f5keys[i].value);
    }
    
    const neededKey = keysArr.join(',');

    let formdata = new FormData();

    formdata.append('file', imageFile.files[0]);

    const res = await fetch(baseUrl + "seperate-image", {
        method: 'POST',
        headers: {
            token: localStorage.getItem('token'),
            f5key: neededKey
        },
        body: formdata
    });

    const response = await res.json();
    console.log(response);
    if(response.ciphertext) {
        theCyphertext.innerText = response.ciphertext;
    }
});

decryptButton.addEventListener('click', async function(e) {
    e.preventDefault();
    let res = await fetch(baseUrl + "decrypt-text", {
        mode: "no-cors",
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            decryptionKey: privateKey.value,
            token: localStorage.getItem('token')
        },
        body: JSON.stringify({
            ciphertext: ciphertext.value
        })
    });

    const response = await res.json();

    console.log(response);
});

