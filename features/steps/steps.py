"""Step definitions -- they drive the real Flask app through its test client."""
from behave import given, then, when

_PASSWORDS = {"alice": "alice-pw", "bob": "bob-pw", "root": "root-pw"}


@given('I am logged in as "{username}"')
def step_login(context, username):
    r = context.client.post(
        "/login", data={"username": username, "password": _PASSWORDS[username]}
    )
    assert r.status_code in (200, 302), f"login failed: {r.status_code}"


@when('I create a note titled "{title}" with body "{body}"')
def step_create(context, title, body):
    context.client.post("/note/new", data={"title": title, "body": body})


@when("I open my dashboard")
def step_dashboard(context):
    context.response = context.client.get("/")


@when('I search for "{query}"')
def step_search(context, query):
    context.response = context.client.get("/search", query_string={"q": query})


@when("I open the admin export")
def step_admin_export(context):
    context.response = context.client.get("/admin/export")


@then('I see "{text}"')
def step_see(context, text):
    body = context.response.get_data(as_text=True)
    assert text in body, f"expected to see {text!r} in the response"


@then('I do not see "{text}"')
def step_not_see(context, text):
    body = context.response.get_data(as_text=True)
    assert text not in body, f"did not expect to see {text!r} in the response"


@then("the response status is {code:d}")
def step_status(context, code):
    assert context.response.status_code == code, (
        f"expected {code}, got {context.response.status_code}"
    )
