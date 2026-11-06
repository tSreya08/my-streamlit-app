import pytest
from payment import PaymentProcessor, PaymentError


def test_charge_success():
    processor = PaymentProcessor(merchant_id="merch_001")
    tx = processor.charge(amount=100.0, card_number="4111-2222-3333-4444")
    assert tx["status"] == "settled"
    assert tx["processing_fee"] == 3.20
    assert tx["net_amount"] == 96.80


def test_refund_success():
    processor = PaymentProcessor(merchant_id="merch_001")
    tx = processor.charge(amount=50.0, card_number="4111-2222-3333-4444")
    ref = processor.refund(tx_id=tx["tx_id"])
    assert ref["status"] == "refunded"
    assert ref["amount"] == -50.0


def test_receipt_formatting():
    processor = PaymentProcessor(merchant_id="merch_001")
    tx = processor.charge(amount=75.0, card_number="4111-2222-3333-4444")
    receipt = processor.format_receipt(tx_id=tx["tx_id"])
    assert "RECEIPT" in receipt
    assert "USD 75.00" in receipt


def test_reconcile_populated_batch():
    processor = PaymentProcessor(merchant_id="merch_001")
    processor.charge(amount=100.0, card_number="4111-2222-3333-4444")
    processor.charge(amount=200.0, card_number="4111-2222-3333-5555")
    summary = processor.reconcile_batch(batch_id="batch_001")
    assert summary["settled_count"] == 2
    assert summary["total_volume"] == 300.0
    assert summary["average_ticket"] == 150.0


def test_empty_batch_reconciliation():
    processor = PaymentProcessor(merchant_id="merch_001")
    # Empty batch should report 0 volume and 0.0 average ticket without crashing
    summary = processor.reconcile_batch(batch_id="batch_empty", transactions=[])
    assert summary["settled_count"] == 0
    assert summary["average_ticket"] == 0.0
