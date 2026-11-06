"""Shopping Cart Module with Loyalty Discount Support."""

LOYALTY_DISCOUNTS = {
    "bronze": 0.05,
    "silver": 0.10,
    "gold": 0.15,
}

class ShoppingCart:
    """Manages user cart items and checkout total computation."""

    def __init__(self, user_tier: str = "standard"):
        self.user_tier = user_tier
        self.items = []

    def add_item(self, name: str, price: float, quantity: int = 1):
        """Add an item to the shopping cart."""
        if price < 0 or quantity <= 0:
            raise ValueError("Invalid price or quantity")
        self.items.append({"name": name, "price": float(price), "quantity": int(quantity)})

    def get_subtotal(self) -> float:
        """Compute total sum of all cart items before tax and discounts."""
        return sum(item["price"] * item["quantity"] for item in self.items)

    def calculate_total(self, tax_rate: float = 0.05) -> float:
        """Compute final order total including loyalty discount and sales tax."""
        subtotal = self.get_subtotal()
        # Look up loyalty discount tier
        discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)
        discount_amount = subtotal * discount_rate
        tax_amount = (subtotal - discount_amount) * tax_rate
        return round((subtotal - discount_amount) + tax_amount, 2)

    def generate_receipt(self) -> str:
        """Format human-readable receipt for the checkout summary."""
        lines = [f"Tier: {self.user_tier}", f"Items count: {len(self.items)}"]
        for it in self.items:
            lines.append(f" - {it['name']} x{it['quantity']}: ${it['price'] * it['quantity']:.2f}")
        lines.append(f"Subtotal: ${self.get_subtotal():.2f}")
        return "\n".join(lines)
