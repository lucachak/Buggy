from .api import create_app


def run_web_ui(args):
    import uvicorn
    app = create_app()
    uvicorn.run(app, host="127.0.0.1", port=getattr(args, "ui_port", 8787),
                log_level="info", access_log=True)


__all__ = ["create_app", "run_web_ui"]
