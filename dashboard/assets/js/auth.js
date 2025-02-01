var token = localStorage.getItem('auth-token');

export async function checkAuth() {
    if (token == null) return false;
    let resp = await fetch('/api/auth', {
        method: 'GET',
        headers: {
            'Authorization': token
        }
    })
    return resp.ok;
}

export async function login(username, password) {
    let resp = await fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username: username,
            password: password
        })
    })
    if (resp.ok) {
        let token = resp.headers.get('Authorization');
        localStorage.setItem('auth-token', token);
        return true;
    }
    return false;
}