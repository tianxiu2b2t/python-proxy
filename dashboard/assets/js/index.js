import { createApp, CTElement } from './cttb.js'
import { checkAuth, login } from './auth.js';
import { CTAlert, CTSVG } from './componts.js';


const app = createApp();
const router = app.routers[0];
const alerts = new CTAlert();

app.style.addStyles({
    "body": {
        "background-color": "var(--background)",
        "height": "100vh"
    }
})

app.style.addGlobals({
    'transition': '150ms cubic-bezier(0.4, 0, 0.2, 1)'   
})

app.style.addThemes('dark', {
    'border-color': 'rgba(196, 196, 196, .257)',
    'box-shadow': 'rgba(0, 0, 0, .5)',
    "main-color": "rgb(244, 209, 180)",
})
app.style.addThemes('light', {
    'border-color': 'rgba(50, 50, 50, .257)',
    'box-shadow': 'rgba(50, 50, 50, .1)',
    "main-color": "rgb(15, 198, 194)",
})
app.i18n.setLang('zh-cn')

class AuthPage extends CTElement {
    constructor() {
        super("div");
        super.classes("auth-page")

        app.i18n.addLanguages('zh-cn', {
            'auth.title': '身份验证',
            'auth.username': '用户名',
            'auth.password': '密码',
            'auth.login': '登录'
        })

        app.i18n.addLanguages('en-us', {
            'auth.title': 'Authentication',
            'auth.username': 'Username',
            'auth.password': 'Password',
            'auth.login': 'Login'
        })


        this.username = CTElement.create("input").classes("auth-input").attr_i18n("placeholder", "auth.username")
        this.password = CTElement.create("input").classes("auth-input").attr_i18n("placeholder", "auth.password")
        this.box_username = CTElement.create("div").classes("auth-input-box").append(this.username)
        this.box_password = CTElement.create("div").classes("auth-input-box").append(this.password)
        this.button = CTElement.create("button").classes("auth-button").i18n("auth.login").listener("click", async () => {
            const username = this.username.inputValue || ''
            const password = this.password.inputValue || ''
            if (username.trim().length == 0 || password.trim().length == 0) {
                alerts.addAlert({
                    type: 'error',
                    message: '用户名或密码不能为空'
                })
                return;
            }
            // processing...
            super.clear()
            super.append(this.processing_container)
            this.processing_loading.style("display", "block")
            this.processing_success.style("display", "none")
            var res = false;
            try {
                res = await login(username, password)
            } catch (e) {
                alerts.addAlert({
                    type: 'error',
                    message: e.message
                })
            } finally {
                if (res) {
                    this.processing_loading.style("display", "none")
                    this.processing_success.style("display", "block")
                } else {
                    alerts.addAlert({
                        type: 'error',
                        message: '登录失败'
                    })
                    super.clear()
                    super.append(this.login_container)
                    return;
                }
                setTimeout(() => {
                    //super.clear()
                    if (res) {
                        app.body.removeChild(this);
                    } else {
                        super.clear()
                        super.append(this.login_container)
                    }
                }, 2000)
            }
        })
        this.form = CTElement.create("div").classes("auth-form").append(
            this.box_username,
            this.box_password
        )
        this.login_container = CTElement.create("div").classes("auth-container").append(
            CTElement.create("h2").classes("auth-title").i18n("auth.title"),
            this.form,
            this.button
        )
        this.processing_loading = CTSVG.loading.classes("ani").style("display", "none");
        this.processing_success = CTSVG.loaded_success.classes("suc").style("display", "none");
        this.processing_container = CTElement.create("div").classes("auth-container").classes("processing").append(
            this.processing_loading,
            this.processing_success
        )
        
        for (const { input, box } of [
            { input: this.username, box: this.box_username },
            { input: this.password, box: this.box_password }
        ]) {
            input.listener("focus", () => {
                console.log(box)
                box.classes("active")
            }).listener("blur", () => {
                box.removeClasses("active")
            })
        }

        console.log(this.login_container)
        super.append(this.login_container)

        app.style.addThemes('dark', {
            'auth-background-color': 'rgba(56, 56, 56, .8)',
        })
        app.style.addThemes('light', {
            'auth-background-color': 'rgba(255, 255, 255, .8)',
        })

        app.style.addStyles({
            ".auth-page": {
                "width": "100vw",
                "height": "100vh",
                "display": "flex",
                "justify-content": "center",
                "align-items": "center",
                "position": "fixed",
                "z-index": "9999",
                "color": "var(--dark-color)",
                "background": "var(--background)"
            },
            ".auth-container": {
                "min-width": "400px",
                "min-height": "256px",
                "border-radius": "10px",
                "background-color": "var(--auth-background-color)",
                "border": "1px solid var(--border-color)",
                "padding": "24px",
                "box-shadow": "0 0 10px var(--box-shadow)",
                "transition": "min-width var(--transition), min-height var(--transition)",
            },
            ".auth-input": {
                "background": "transparent",
                "outline": "none",
                "width": "100%",
                "height": "100%",
                "font-size": "0.875rem",
                "border": "none",
                "padding": "0 4px 0 4px",
                "transition": "border-color var(--transition)",
                "color": "inherit"
            },
            ".auth-form": {
                "display": "flex",
                "flex-direction": "column",
                "gap": "15px",
                "margin-top": "20px",
                "margin-bottom": "20px",
            },
            ".auth-input-box": {
                "padding": "5px",
                "height": "2.5rem",
                "border": "1px solid var(--border-color)",
                "border-radius": "4px",
                "transition": "border-color var(--transition), padding var(--transition)",
            },
            ".auth-input-box:hover": {
                "border": "1px solid var(--main-color)",
            },
            ".auth-input-box.active": {
                "border": "1px solid var(--main-color)",
                "box-shadow": "0 0 1px var(--main-color)",
            },
            ".auth-button": {
                "width": "100%",
                "height": "2.5rem",
                "border": "none",
                "border-radius": "4px",
                "background-color": "var(--main-color)",
                "color": "var(--color)",
                "font-size": "0.875rem",
                "cursor": "pointer",
            },
            "@media (max-width: 600px)": {
                ".auth-container": {
                    "min-width": "100%",
                    "min-height": "100%",
                    "border-radius": "0",
                    "padding": "0",
                }
            },

            ".auth-container.processing": {
                "display": "flex",
                "flex-direction": "column",
                "justify-content": "center",
                "align-items": "center",
            },
            ".auth-container.processing svg": {
                "fill": "var(--main-color)",
                "margin": "auto",
                "display": "block",
                "width": "auto",
                "height": "96px",
            },
            ".auth-container.processing svg.suc": {
                "fill": "rgba(0, 250, 0, 0.8)",
            },
            ".auth-container.processing svg.ani": {
                "animation": "auth-spin 1s linear infinite",
            },
            "@keyframes auth-spin": {
                "0%": {
                    "transform": "rotate(0deg)"
                },
                "100%": {
                    "transform": "rotate(360deg)"
                }
            }
        })
    }
}

const authPage = new AuthPage();

async function main() {
    // first check auth
    if (!await checkAuth()) {
        app.body.append(authPage)
        return;
    }
}

main();