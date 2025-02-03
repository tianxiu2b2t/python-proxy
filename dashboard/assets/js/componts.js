import { app, CTElement, raf } from './cttb.js'

export class CTAlert extends CTElement {
    static types = {
        info: "info",
        success: "success",
        warning: "warning",
        error: "error",
    }
    static defaultOptions = {
        type: CTAlert.types.info,
        message: "",
        duration: 3000,
    }
    constructor() {
        super("div").classes("c-alerts");
        this.alerts = [];
        app.body.append(this);

        app.style.addStyles({
            ".c-alerts": {
                "position": "fixed",
                "z-index": "999999",
                "width": "100%",
                "height": "0px",
                "top": "0",
                "display": "flex",
                "flex-direction": "column",
                "align-items": "center",
            },
            ".c-alerts .c-alert": {
                "position": "relative",
                "height": "0px",
                "width": "240px",
                "display": "flex",
                "align-items": "center",
                "height": "32px",
                "padding": "4px 8px 4px 8px",
                "border-radius": "4px",
                "margin-top": "16px",
                "z-index": "9999999",
                "transform": "translateY(-150%)",
                "transition": "transform 500ms cubic-bezier(0.4, 0, 0.2, 1), opacity 500ms cubic-bezier(0.4, 0, 0.2, 1), height 500ms cubic-bezier(0.4, 0, 0.2, 1), top 500ms cubic-bezier(0.4, 0, 0.2, 1)",
                "opacity": "0",
                "top": "0"
            },
            ".c-alerts .c-alert.show": {
                "transform": "translateY(0)",
                "opacity": "1",
                "height": "32px",
            },
            ".c-alerts .c-alert.leave": {
                "transform": "translateY(-150%)",
                "opacity": "0",
                "height": "0px",
            },
            ".c-alerts .c-alert svg": {
                "width": "14px",
                "height": "14px",
                "margin-right": "1px",
            },
            ".c-alerts .c-alert span": {
                "width": "100%",
                "font-size": "14px",
                "font-weight": "500",
                "line-height": "1.5",
                "text-align": "center",
            },
            ".c-alerts .c-alert.info": {
                "background-color": "#e0f7fa",
                "color": "#018786",
                "fill": "#018786",
                "box-shadow": "0px 3px 1px -2px rgb(0 135 130 / 20%), 0px 2px 2px 0px rgb(0 135 130 / 14%), 0px 1px 5px 0px rgb(0 135 130 / 12%)"
            },
            ".c-alerts .c-alert.success": {
                "background-color": "#e8f5e9",
                "color": "#1b5e20",
                "fill": "#1b5e20",
                "box-shadow": "0px 3px 1px -2px rgb(27 94 32 / 20%), 0px 2px 2px 0px rgb(27 94 32 / 14%), 0px 1px 5px 0px rgb(27 94 32 / 12%)"
            },
            ".c-alerts .c-alert.warning": {
                "background-color": "#fff3e0",
                "color": "#827717",
                "fill": "#827717",
                "box-shadow": "0px 3px 1px -2px rgb(130 119 23 / 20%), 0px 2px 2px 0px rgb(130 119 23 / 14%), 0px 1px 5px 0px rgb(130 119 23 / 12%)"
            },
            ".c-alerts .c-alert.error": {
                "background-color": "#ffebee",
                "color": "#b71c1c",
                "fill": "#b71c1c",
                "box-shadow": "0px 3px 1px -2px rgb(183 28 28 / 20%), 0px 2px 2px 0px rgb(183 28 28 / 14%), 0px 1px 5px 0px rgb(183 28 28 / 12%)"
            }
        })
    }
    addAlert(
        options = defaultOptions
    ) {
        let merged = { ...CTAlert.defaultOptions, ...options };
        this.render(merged);
    }
    render(options) {
        let alert = CTElement.create("div").classes("c-alert").classes(options.type);
        if (CTSVG[options.type] != undefined) {
            alert.append(CTSVG[options.type]);
        }
        alert.append(CTElement.create("span").text(options.message))
        super.append(alert);
        raf(() => {
            alert.classes("show");
            setTimeout(() => {
                alert.classes("leave")
                alert.listener("transitionend", () => {
                    alert.remove();
                }, {
                    once: true
                })
            }, options.duration)
        })
    }
    calcTop() {
        let top = 0;
        if (this.alerts.length > 0) {
            top = this.alerts[this.alerts.length - 1].$base.offsetHeight;
        }
        return top;
    }
}

export class CTSVG {
    static _parse(element) {
        return CTElement.create(document.createRange().createContextualFragment(element).childNodes[0]);
    }
    static get error() {
        return CTSVG._parse('<svg xmlns="http://www.w3.org/2000/svg" viewBox="64 64 896 896"><path d="M512 64c247.4 0 448 200.6 448 448S759.4 960 512 960 64 759.4 64 512 264.6 64 512 64zm127.98 274.82h-.04l-.08.06L512 466.75 384.14 338.88c-.04-.05-.06-.06-.08-.06a.12.12 0 00-.07 0c-.03 0-.05.01-.09.05l-45.02 45.02a.2.2 0 00-.05.09.12.12 0 000 .07v.02a.27.27 0 00.06.06L466.75 512 338.88 639.86c-.05.04-.06.06-.06.08a.12.12 0 000 .07c0 .03.01.05.05.09l45.02 45.02a.2.2 0 00.09.05.12.12 0 00.07 0c.02 0 .04-.01.08-.05L512 557.25l127.86 127.87c.04.04.06.05.08.05a.12.12 0 00.07 0c.03 0 .05-.01.09-.05l45.02-45.02a.2.2 0 00.05-.09.12.12 0 000-.07v-.02a.27.27 0 00-.05-.06L557.25 512l127.87-127.86c.04-.04.05-.06.05-.08a.12.12 0 000-.07c0-.03-.01-.05-.05-.09l-45.02-45.02a.2.2 0 00-.09-.05.12.12 0 00-.07 0z"></path></svg>')
    }
    static get loading() {
        return CTSVG._parse('<svg focusable="false" width="1em" height="1em" viewBox="0 0 1024 1024"><path d="M988 548c-19.9 0-36-16.1-36-36 0-59.4-11.6-117-34.6-171.3a440.45 440.45 0 00-94.3-139.9 437.71 437.71 0 00-139.9-94.3C629 83.6 571.4 72 512 72c-19.9 0-36-16.1-36-36s16.1-36 36-36c69.1 0 136.2 13.5 199.3 40.3C772.3 66 827 103 874 150c47 47 83.9 101.8 109.7 162.7 26.7 63.1 40.2 130.2 40.2 199.3.1 19.9-16 36-35.9 36z"></path></svg>')
    }
    static get loaded_success() {
        return CTSVG._parse('<svg width="1em" height="1em" viewBox="64 64 896 896"><path d="M699 353h-46.9c-10.2 0-19.9 4.9-25.9 13.3L469 584.3l-71.2-98.8c-6-8.3-15.6-13.3-25.9-13.3H325c-6.5 0-10.3 7.4-6.5 12.7l124.6 172.8a31.8 31.8 0 0051.7 0l210.6-292c3.9-5.3.1-12.7-6.4-12.7z"></path><path d="M512 64C264.6 64 64 264.6 64 512s200.6 448 448 448 448-200.6 448-448S759.4 64 512 64zm0 820c-205.4 0-372-166.6-372-372s166.6-372 372-372 372 166.6 372 372-166.6 372-372 372z"></path></svg>')
    }
    static get moon() {
        return CTSVG._parse('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M12 11.807A9.002 9.002 0 0 1 10.049 2a9.942 9.942 0 0 0-5.12 2.735c-3.905 3.905-3.905 10.237 0 14.142 3.906 3.906 10.237 3.905 14.143 0a9.946 9.946 0 0 0 2.735-5.119A9.003 9.003 0 0 1 12 11.807z"></path></svg>')
    }
    static get sun() {
        return CTSVG._parse('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path d="M6.995 12c0 2.761 2.246 5.007 5.007 5.007s5.007-2.246 5.007-5.007-2.246-5.007-5.007-5.007S6.995 9.239 6.995 12zM11 19h2v3h-2zm0-17h2v3h-2zm-9 9h3v2H2zm17 0h3v2h-3zM5.637 19.778l-1.414-1.414 2.121-2.121 1.414 1.414zM16.242 6.344l2.122-2.122 1.414 1.414-2.122 2.122zM6.344 7.759 4.223 5.637l1.415-1.414 2.12 2.122zm13.434 10.605-1.414 1.414-2.122-2.122 1.414-1.414z"></path></svg>')
    }
}