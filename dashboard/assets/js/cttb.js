export var app = null;
var style = null
var i18n = null;

export class CTElement {
    constructor(
        tag = 'div',
    ) {
        if (typeof tag == 'string') {
            this.$base = document.createElement(tag);
        } else if (CTElement.isDOM(tag)) {
            this.$base = tag;
        } else throw new Error('Tag must be a string');
        this._children = [];
        this._i18n = {
            key: null,
            params: null
        }
        this._attr_i18n = {};
        
        // add into app
        if (app.elements.map(e => e.$base).includes(this.$base)) return;
        app.elements.push(this);
    }
    append(...children) {
        for (let child of children) {
            if (CTElement.isDOM(child)) {
                child = new CTElement(child);
            }
            if (!(child instanceof CTElement)) {
                throw new Error('Child must be a CTElement');
            }
            this.$base.appendChild(child.$base);
            this._children.push(child);
        }
        return this;
    }
    removeChild(child) {
        if (CTElement.isDOM(child)) {
            child = new CTElement(child);
        }
        if (!(child instanceof CTElement)) {
            throw new Error('Child must be a CTElement');
        }
        this.$base.removeChild(child.$base);
        this._children = this._children.filter(c => c.$base != child.$base);
        return this;
    }
    clear() {
        console.log(this)
        this._children = [];
        while (this.$base.firstChild != null) {
            this.$base.removeChild(this.$base.firstChild);
        }
        return this;
    }
    classes(...classes) {
        this.$base.classList.add(...classes);
        return this;
    }
    style(key, value) {
        this.$base.style.setProperty(key, value);
        return this;
    }
    styles(styles) {
        for (let key in styles) {
            this.$base.style.setProperty(key, styles[key]);
        }
        return this;
    }
    removeClasses(...classes) {
        this.$base.classList.remove(...classes);
        return this;
    }
    text(text) {
        this.$base.innerText = text;
        return this;
    }
    html(html) {
        this.$base.innerHTML = html;
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
    i18n(key, params) {
        this._i18n = {
            key, 
            params
        }
        this._render_i18n();
        return this;
    }
    t18n(params) {
        this._i18n.params = params;
        this._render_i18n();
        return this;
    }
    _render_i18n() {
        if (this._i18n.key) {
            this.$base.innerHTML = i18n.t(this._i18n.key, this._i18n.params);
        }
    }
    attr(name, value) {
        this.$base.setAttribute(name, value);
        return this;
    }
    attr_i18n(name, key, params) {
        this._attr_i18n[name] = {
            key,
            params
        }
        this._render_attr_i18n();
        return this;
    }
    _render_attr_i18n() {
        for (let name in this._attr_i18n) {
            this.$base.setAttribute(name, i18n.t(this._attr_i18n[name].key, this._attr_i18n[name].params));
        }
    }
    get children() {
        return this._children;
    }
    get base() {
        return this.$base;
    }
    get inputValue() {
        return this.$base.value;
    }
    static isDOM(o) {
        return (
            typeof HTMLElement === "object" ? o instanceof HTMLElement : //DOM2
            o && typeof o === "object" && o !== null && o.nodeType === 1 && typeof o.nodeName==="string"
        );
    }
    static create(tag) {
        return new CTElement(tag);
    }
}
class CTStyle {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'auto';
        this.styles = {};
        this.medias = {}
        this.themes = {};
        this.root = {}

        this._raf = null;

        this.$style = document.createElement('style');

        document.head.appendChild(this.$style);

        this.loadDefaultTheme();
    }
    loadDefaultTheme() {
        this.addThemes("dark", {
            "background": "rgb(24, 24, 24)",
            "color": "rgba(0, 0, 0, 0.7)",
            "dark-color": "rgba(255, 255, 255, 0.8)"
        })
        this.addThemes("light", {
            "background": "rgb(248, 248, 247)",
            "color": "rgba(255, 255, 255, 0.7)",
            "dark-color": "rgba(0, 0, 0, 0.8)"
        })
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
        this.render();
    }
    addGlobal(key, value) {
        this.root[key] = value;
        this.render();
    }
    addGlobals(values) {
        for (let key in values) {
            this.addGlobal(key, values[key]);
        }
    }
    addStyle(key, value) {
        if (!key.startsWith("@")) {
            this.styles[key] = (this.styles[key] || '') + ";" + this._parseToString(value);
        } else {
            if (!(key in this.medias)) this.medias[key] = []
            if (this.medias[key].indexOf(value) == -1) this.medias[key].push(this._parseToString(value));
            this.styles[key] = this.medias[key].join(";");
        }
        this.render();
    }
    addStyles(values) {
        for (let key in values) {
            this.addStyle(key, values[key]);
        }
    }
    addThemes(theme, values) {
        for (let key in values) {
            this.addTheme(theme, key, values[key]);
        }
        this.render();
    }
    addTheme(theme, key, value) {
        if (!(theme in this.themes)) this.themes[theme] = {};
        if (!(key in this.themes[theme])) this.themes[theme][key] = [];
        this.themes[theme][key].push(value);
        this.render();
    }
    render() {
        if (this._raf != null) return;
        this._raf = raf(() => {
            this._render();
        })
    }
    _render() {
        this._raf = null;
        // first remove all styles

        var styles = {};
        // first theme
        var theme = this.themes[this.isDark() ? 'dark' : 'light'] || {};
        var theme_values = {};
        for (let key in theme) {
            theme_values[`--${key}`] = this._parseToString(theme[key]);
        }
        for (let key in this.root) {
            theme_values[`--${key}`] = this._parseToString(this.root[key]);
        }
        styles[':root'] = this._parseToString(theme_values);
        for (let key in this.styles) {
            styles[key] = this.styles[key];
        }
        // then add styles
        const styleRules = Object.entries(styles).map(([name, style]) => style == null ? "" : `${name}{${style}}`.replaceAll(/\n|\t|\r/g, "").replaceAll(/\s\s/g, " "));
        requestAnimationFrame(() => {
            this._clear_render()
            styleRules.forEach(styleRule => {
                this._sheet_render(styleRule);
            })
        })
    }
    _parseToString(object) {
        if (Array.isArray(object)) {
            return object.map(this._parseToString).join(";");
        } else if (typeof object == "object") {
            return Object.entries(object).map(([key, value]) => typeof value === "object" ? `${key}{${this._parseToString(value)}}` : `${key}:${this._parseToString(value)};`).join("");
        } else {
            return object.toString();
        }
    }
    _clear_render() {
        this._style_sheet = this.$style.sheet;
        if (this._style_sheet) {
            this._clear_render = () => {
                while (this._style_sheet.cssRules.length > 0) {
                    this._style_sheet.deleteRule(0);
                }
            }
        } else {
            this._clear_render = () => {
                while (this.$style.childNodes.length > 0) {
                    this.$style.removeChild(this.$style.childNodes[0]);
                }
            }
        }
        this._clear_render()
    }
    _sheet_render(styleRule) {
        this._style_sheet = this.$style.sheet;
        if (this._style_sheet) {
            try {
                var handler = (styleRule) => {
                    this._style_sheet.insertRule(styleRule, this._style_sheet.cssRules.length);
                }
                handler(styleRule)
                this._sheet_render = handler;
                return;
            } catch (e) {
                console.log(e)
            }
        }
        this._sheet_render = (styleRule) => this.$style.appendChild(document.createTextNode(styleRule));
        this._sheet_render()
    }
}
class CTApplication {
    constructor() {
        app = this;
        // find preloader
        this.routers = [];
        this.elements = [];
        this.i18n = new CTI18N();
        this.logger = console;
        this.style = style;

        this.$document_body = document.body;
        this._body = new CTElement(this.$document_body);

        this.init();
    }
    init() {
        this.routers.push(new CTRouter("/"))
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
    createElement(tag) {
        return new CTElement(tag);
    }
    get body() {
        return this._body;
    }
}
class CTRouteEvent {

}
class CTRoute {
    constructor(
        path,
        func
    ) {
        this.path = path; 
        this.func = func;
    }
}
class CTRouter {
    constructor(
        prefix = "/",
    ) {
        this.routes = [];
        this.prefix = prefix;
    }
    addRoute(path, func) {
        this.routes.push(new CTRoute(path, func));
    }
    
}
class CTI18NChangeEvent extends Event {
    constructor() {
        super("cti18nchange");
    }
}
class CTI18N {
    constructor() {
        i18n = this;
        this.defaultLang = "zh-cn"
        this.currentLang = this.defaultLang;
        this.languages = {}
    }
    setLang(lang) {
        this.currentLang = lang;
        // trigger event;
        window.dispatchEvent(new CTI18NChangeEvent());
    }
    addLanguage(lang, key, value) {
        if (!(lang in this.languages)) this.languages[lang] = {};
        this.languages[lang][key] = value;
    }
    addLanguages(lang, obj) {
        for (let key in obj) {
            this.addLanguage(lang, key, obj[key]);
        }
    }
    t(key, params) {
        let lang = this.currentLang;
        if (!(lang in this.languages) || !(key in this.languages[lang])) return key;
        let value = this.languages[lang][key];
        if (params != null) {
            for (let key in params) {
                value = value.replace("{" + key + "}", params[key]);
            }
        }
        return value;
    }
}
export function raf(callback) {
    return requestAnimationFrame(callback);
}

export function createApp() {
    if (app == null) {
        style = new CTStyle();
        app = new CTApplication();
        app.init();
        globalThis.app = app;
    }
    return app;
}
export function createRouter(
    prefix = "/"
) {
    return new CTRouter(prefix);
}