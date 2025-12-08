# tests/test_operation_result.py

from dredge.aws_ir.models import OperationResult


def test_operation_result_initial_state():
    r = OperationResult(operation="test-op", target="foo", success=True)
    assert r.success is True
    assert r.errors == []
    assert isinstance(r.details, dict)


def test_operation_result_add_error_marks_failure():
    r = OperationResult(operation="test-op", target="foo", success=True)
    r.add_error("something went wrong")
    assert r.success is False
    assert r.errors == ["something went wrong"]
