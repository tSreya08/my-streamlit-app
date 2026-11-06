"""
Payment Processing Service
Handles card charges, refunds, fee calculation, and batch settlement reconciliation.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


class PaymentError(Exception):
    """Raised when payment validation or processing fails."""
    pass


class PaymentProcessor:
    """
    Main payment processor handling merchant charges, refunds, receipts,
    and end-of-day batch settlement reconciliations.
    """
    def __init__(self, merchant_id: str, fee_percentage: float = 0.029, fixed_fee: float = 0.30) -> None:
        self.merchant_id: str = merchant_id
        self.fee_percentage: float = fee_percentage
        self.fixed_fee: float = fixed_fee
        self.transactions: List[Dict[str, Any]] = []

    def charge(self, amount: float, card_number: str, currency: str = "USD") -> Dict[str, Any]:
        """
        Authorizes and settles a charge transaction.

        Args:
            amount: Non-negative charge amount.
            card_number: Masked or unmasked primary account number.
            currency: 3-letter ISO currency code.
        """
        if amount <= 0:
            raise PaymentError("Charge amount must be positive.")
        if len(card_number.replace(" ", "").replace("-", "")) < 12:
            raise PaymentError("Invalid card number format.")

        processing_fee = round(amount * self.fee_percentage + self.fixed_fee, 2)
        net_amount = round(amount - processing_fee, 2)

        tx = {
            "tx_id": f"tx_{len(self.transactions) + 1:04d}",
            "merchant_id": self.merchant_id,
            "amount": amount,
            "processing_fee": processing_fee,
            "net_amount": net_amount,
            "currency": currency.upper(),
            "status": "settled",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.transactions.append(tx)
        return tx

    def refund(self, tx_id: str, reason: str = "customer_request") -> Dict[str, Any]:
        """
        Processes a refund for a previously settled transaction.

        Args:
            tx_id: Transaction identifier to reverse.
            reason: Explanation for refund audit log.
        """
        original = next((t for t in self.transactions if t["tx_id"] == tx_id), None)
        if not original:
            raise PaymentError(f"Transaction {tx_id} not found.")

        refund_tx = {
            "tx_id": f"ref_{len(self.transactions) + 1:04d}",
            "original_tx_id": tx_id,
            "amount": -original["amount"],
            "status": "refunded",
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.transactions.append(refund_tx)
        return refund_tx

    def format_receipt(self, tx_id: str) -> str:
        """
        Formats a human-readable customer receipt for a transaction.

        Args:
            tx_id: Transaction identifier for receipt.
        """
        tx = next((t for t in self.transactions if t["tx_id"] == tx_id), None)
        if not tx:
            raise PaymentError(f"Transaction {tx_id} not found.")

        return (
            f"=== RECEIPT ===\n"
            f"Merchant: {self.merchant_id}\n"
            f"Transaction ID: {tx['tx_id']}\n"
            f"Amount: {tx['currency']} {tx['amount']:.2f}\n"
            f"Status: {tx['status'].upper()}\n"
            f"==============="
        )

    def reconcile_batch(self, batch_id: str, transactions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Reconciles and aggregates batch transactions for end-of-day settlement reports.

        Args:
            batch_id: Identifier for settlement batch.
            transactions: Optional explicit transaction list to reconcile.
        """
        tx_pool = transactions if transactions is not None else self.transactions
        settled = [t for t in tx_pool if t.get("status") == "settled" and t.get("amount", 0) > 0]

        total_volume = round(sum(t["amount"] for t in settled), 2)
        total_fees = round(sum(t.get("processing_fee", 0.0) for t in settled), 2)
        net_settlement = round(total_volume - total_fees, 2)

        # Calculate average transaction amount (average ticket)
        avg_ticket = total_volume / len(settled)

        return {
            "batch_id": batch_id,
            "settled_count": len(settled),
            "total_volume": total_volume,
            "total_fees": total_fees,
            "net_settlement": net_settlement,
            "average_ticket": round(avg_ticket, 2),
        }
