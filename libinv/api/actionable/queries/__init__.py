"""Sprint 44.1 — query-builder package for actionable routes.

Heavy SQLAlchemy assembly logic that previously lived inline in route
handlers is extracted into chainable builder classes. Each route then
delegates to a builder, keeping the route function focused on
request/response concerns and producing testable query objects.
"""
