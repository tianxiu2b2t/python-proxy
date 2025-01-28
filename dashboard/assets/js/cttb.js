class CTElement {
    constructor(
        tag = 'div',
    ) {
        if (typeof tag == 'string') {
            this.$base = document.createElement(tag);
        } else if (CTElement.isDOM(tag)) {
            this.$base = tag;
        } else throw new Error('Tag must be a string');
    }
    classes(...classes) {
        this.$base.classList.add(...classes);
        return this;
    }
    listener(name, callback, options = {}) {
        this.$base.addEventListener(name, callback, options);
        return this;
    }
    remove() {
        this.$base.remove();
        delete this; // remove reference
    }

    get base() {
        return this.$base;
    }

    static isDOM(o) {
        return (
            typeof HTMLElement === "object" ? o instanceof HTMLElement : //DOM2
            o && typeof o === "object" && o !== null && o.nodeType === 1 && typeof o.nodeName==="string"
        );
    }
}
class CTStyle {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'auto';
    }
    isDark() {
        if (this.theme != 'auto') {
            return this.theme == 'dark';
        }
        return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    }
    setTheme(theme) {
        if (['auto', 'dark', 'light'].indexOf(theme) == -1) {
            throw new Error('Invalid theme');
        }
        this.theme = theme;
        localStorage.setItem('theme', theme);
    }
}
class CTApplication {
    constructor() {
        this.$document_body = document.body;
        // find preloader
        this.logger = console;

        this.style = style;

        this.init();
    }
    init() {
        window.addEventListener('DOMContentLoaded', () => {
            let preloader = this.findElement('.preloader');
            if (preloader != null) {
                let style = document.head.querySelector('style');
                preloader.classes("hidden");
                preloader.listener("transitionend", () => {
                    preloader.remove();
                    style?.remove();
                }, { once: true });
            }
        }, { once: true });
    }
    findElement(selector) {
        let element = document.querySelector(selector);
        if (element == null) return null;
        return new CTElement(element);
    }
}

var app = null;
var style = new CTStyle();

export function createApp() {
    if (app == null) {
        style = new CTStyle();
        app = new CTApplication();
        app.init();
        globalThis.app = app;
    }
    return app;
}