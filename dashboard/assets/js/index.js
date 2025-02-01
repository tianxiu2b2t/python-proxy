import { createApp, createRouter } from './cttb.js'
import { checkAuth } from './auth.js';


const app = createApp();
const router = app.routers[0];

app.style.addStyles({
    "body": {
        "background-color": "var(--background)",
        "height": "100vh"
    }
})
async function main() {
    // first check auth
    if (!await checkAuth()) {
        console.log("not logged in")
        return;
    }
}

main();