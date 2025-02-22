import json

import flask_login  # type: ignore
from flask import Response, request
from flask_login import user_loaded_from_request, user_logged_in
from werkzeug.exceptions import Unauthorized

import contexts
from configs import dify_config
from dify_app import DifyApp
from libs.passport import PassportService
from services.account_service import AccountService, RegisterService, TenantService

login_manager = flask_login.LoginManager()


# Flask-Login configuration
@login_manager.request_loader
def load_user_from_request(request_from_flask_login):
    """Load user based on the request."""
    if request.blueprint not in {"console", "inner_api"}:
        return None
    # Check if the user_id contains a dot, indicating the old format
    auth_header = request.headers.get("Authorization", "")

    # EDC hick start
    aksk_header = request.headers.get(dify_config.EDC_SECRET_HEADER_NAME, "")
    import click
    # click.echo(f"Step 1: Retrieved aksk_header value: {aksk_header}")

    aksk_user = request.headers.get(dify_config.EDC_TRUSTED_USER_ID_HEADER_NAME, "")
    # click.echo(f"Step 2: Retrieved aksk_user value: {aksk_user}")

    aksk_user_name = request.headers.get(dify_config.EDC_TRUSTED_USER_NAME_HEADER_NAME, "")
    # click.echo(f"Step 3: Retrieved aksk_user_name value: {aksk_user_name}")

    if aksk_header and aksk_user:
        # click.echo("Step 4: Both aksk_header and aksk_user are present, proceeding with authentication...")
        if aksk_header != dify_config.EDC_SECRET:
            click.echo(f"Step 5: aksk_header does not match the predefined , returning None...")
            return None
        account_email = aksk_user + '@whlyy-edc.com'
        # click.echo(f"Step 6: Constructed account_id: {account_email}")
        logged_in_account = AccountService.load_user_by_email(email=account_email)
        # click.echo(f"Step 7: Loaded account: {logged_in_account}")
        if not logged_in_account:
            click.echo("Step 8: Account not found, proceeding with registration...")
            logged_in_account = RegisterService.sighup(email=account_email, name=aksk_user_name,
                                                         password='HdD@4z|up7y?.NAy2fh7&3`9oug')
            click.echo(f"Step 9: Registered new account: {logged_in_account}")

        if logged_in_account:
            return AccountService.load_logged_in_account(account_id=logged_in_account.id)
    # EDC hick end

    if not auth_header:
        auth_token = request.args.get("_token")
        if not auth_token:
            raise Unauthorized("Invalid Authorization token.")
    else:
        if " " not in auth_header:
            raise Unauthorized("Invalid Authorization header format. Expected 'Bearer <api-key>' format.")
        auth_scheme, auth_token = auth_header.split(None, 1)
        auth_scheme = auth_scheme.lower()
        if auth_scheme != "bearer":
            raise Unauthorized("Invalid Authorization header format. Expected 'Bearer <api-key>' format.")

    decoded = PassportService().verify(auth_token)
    user_id = decoded.get("user_id")

    logged_in_account = AccountService.load_logged_in_account(account_id=user_id)
    return logged_in_account


@user_logged_in.connect
@user_loaded_from_request.connect
def on_user_logged_in(_sender, user):
    """Called when a user logged in."""
    if user:
        contexts.tenant_id.set(user.current_tenant_id)


@login_manager.unauthorized_handler
def unauthorized_handler():
    """Handle unauthorized requests."""
    return Response(
        json.dumps({"code": "unauthorized", "message": "Unauthorized."}),
        status=401,
        content_type="application/json",
    )


def init_app(app: DifyApp):
    login_manager.init_app(app)
