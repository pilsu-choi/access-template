import logging

from dotenv import load_dotenv

from sso_template.app import create_app


class RedactAuthQuery(logging.Filter):
    """uvicorn access logs include the full query string, which on /auth/* carries
    authorization codes and SAML messages. Drop the query for those paths."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            path = args[2]
            if path.startswith("/auth/") and "?" in path:
                record.args = (*args[:2], path.split("?", 1)[0] + "?[redacted]", *args[3:])
        return True


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logging.getLogger("uvicorn.access").addFilter(RedactAuthQuery())

load_dotenv()  # .env -> os.environ for ${VAR} references in tenants.yaml
app = create_app()
