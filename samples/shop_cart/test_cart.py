import pytest
from cart import ShoppingCart

def test_add_item():
    cart = ShoppingCart()
    cart.add_item("Book", 15.0, 2)
    assert cart.get_subtotal() == 30.0

def test_loyalty_gold_discount():
    cart = ShoppingCart(user_tier="gold")
    cart.add_item("Monitor", 200.0, 1)
    # 200 subtotal - 15% discount ($30) = $170 + 5% tax ($8.50) = 178.50
    assert cart.calculate_total(tax_rate=0.05) == 178.50

def test_standard_user_checkout():
    cart = ShoppingCart(user_tier="standard")
    cart.add_item("Keyboard", 50.0, 1)
    # Standard users get 0% discount: 50 + 5% tax ($2.50) = 52.50
    assert cart.calculate_total(tax_rate=0.05) == 52.50
