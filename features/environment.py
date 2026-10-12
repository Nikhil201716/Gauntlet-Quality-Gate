"""Behave hooks: a fresh, freshly seeded app and client for every scenario."""
import os
import sys

sys.path.insert(0, os.getcwd())

from app.web import create_app  # noqa: E402


def before_scenario(context, scenario):
    context.app = create_app()
    context.client = context.app.test_client()
    context.response = None
