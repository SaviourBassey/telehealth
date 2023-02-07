const username = document.getElementById('username');
const email = document.getElementById('email');
const password = document.getElementById('password');
const registerButton = document.getElementById('registerButton');

const loginEmail = document.getElementById('loginEmail');
const loginPassword = document.getElementById('loginPassword');
const loginButton = document.getElementById('loginButton');

const newPassword = document.getElementById('newPassword');
const newPasswordButton = document.getElementById('newPasswordButton');


registerButton.addEventListener('click', async function(e) {
    e.preventDefault();
    const res = await fetch(baseUrl + 'register', {
        method: 'POST',
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            username: username.value,
            email: email.value,
            password: password.value
        })
    });

    response = await res.json();
    console.log(response);

});

loginButton.addEventListener('click', async function(e) {
    e.preventDefault();
    const res = await fetch(baseUrl + 'login', {
        method: 'POST',
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            email: loginEmail.value,
            password: loginPassword.value
        })
    });
    try {
        response = await res.json();
        // console.log(response);
        if(!response.token) {
            console.log(response.detail);
            window.FlashMessage.success(response.detail);
        } else {
            localStorage.setItem('token', response.token);
            location.assign('/dashboard/index.html');
        }
        
    } catch (error) {
        console.log("Error", error);
    }
    
});

newPasswordButton.addEventListener('click', async function(e) {
    e.preventDefault();

    const res = await fetch(baseUrl + 'forget-password', {
        method: 'POST',
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            password: newPassword.value
        })
    });

    response = await res.json();
    console.log(response);
});
