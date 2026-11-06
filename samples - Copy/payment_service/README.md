# Payment Processing Service (PHANTOM Demo Incident)

A lightweight Python payment gateway service demonstrating transaction authorization, settlement, customer refund processing, and batch reconciliation metrics.

---

## 1. Project Overview

The service defines `PaymentProcessor` in `payment.py`:
- `charge(amount, card_number, currency)`: Validates and settles customer charges, calculating processing fees (`2.9% + $0.30`).
- `refund(tx_id, reason)`: Records and processes transaction reversals.
- `format_receipt(tx_id)`: Generates printable text receipts for customer transactions.
- `reconcile_batch(batch_id, transactions)`: Aggregates settled transactions, calculates gross volume, processing fees, net payout, and the average ticket size.

---

## 2. Bug Summary & Reproduction

When reconciling an empty batch (e.g., during off-peak maintenance reconciliation, a newly initialized merchant account, or when no transactions settle within the reporting window), the application crashes with an unhandled `ZeroDivisionError`.

### How to Reproduce

Run the test suite with `pytest`:

```bash
pytest test_payment.py
```

### Stack Trace

```text
Traceback (most recent call last):
  File "test_payment.py", line 40, in test_empty_batch_reconciliation
    summary = processor.reconcile_batch(batch_id="batch_empty", transactions=[])
  File "payment.py", line 75, in reconcile_batch
    avg_ticket = total_volume / len(settled)
ZeroDivisionError: division by zero
```

---

## 3. Historical Code Evolution (Git Blame & Commits)

Inspection of the Git log reveals:

1. `78a46ff` — `feat: Initial payment processing implementation` (Marcus Ray)  
   *Initial baseline with charge, refund, and basic reconciliation.*
2. `c3ab04e` — `feat: Add average ticket calculation to batch reconciliation` (Marcus Ray)  
   *⚠️ **INTRODUCING COMMIT**: Added `avg_ticket = total_volume / len(settled)` without checking for empty collections.*
3. `02d1f38` — `feat: Add receipt formatting for customer transactions` (Sarah Lin)  
   *Added receipt template generation.*
4. `HEAD` — `docs: Add method docstrings, type annotations, and README documentation` (Alice Dev)  
   *Current commit with documentation.*

Notice that the bug was introduced in an **earlier commit (`c3ab04e`)**, not in the latest commit.

---

## 4. Root Cause Analysis

In `payment.py`, lines 74–75:

```python
# Calculate average transaction amount (average ticket)
avg_ticket = total_volume / len(settled)
```

When `transactions` is empty or contains no settled transactions, `settled` evaluates to `[]` (`len(settled) == 0`). Dividing `total_volume` by `len(settled)` triggers `ZeroDivisionError: division by zero`.

---

## 5. Expected Correct Behavior

When an account or batch has 0 settled transactions:
- `settled_count` must be `0`.
- `total_volume` must be `0.0`.
- `average_ticket` must safely return `0.0` without raising an exception.

### Expected Minimal Fix

```python
<<<<
        # Calculate average transaction amount (average ticket)
        avg_ticket = total_volume / len(settled)
====
        # Calculate average transaction amount (average ticket)
        avg_ticket = (total_volume / len(settled)) if settled else 0.0
>>>>
```
