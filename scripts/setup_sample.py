import os
import sys
import shutil
import subprocess

mingit = os.path.expandvars(r"%LOCALAPPDATA%\Programs\MinGit\cmd\git.exe")
env = os.environ.copy()
env["GIT_PYTHON_GIT_EXECUTABLE"] = mingit
env["PATH"] = os.path.dirname(mingit) + os.pathsep + env.get("PATH", "")

import stat

def remove_readonly(func, path, excinfo):
    os.chmod(path, stat.S_IWRITE)
    func(path)

sample_dir = os.path.abspath("samples/shop_cart")
if os.path.exists(sample_dir):
    try:
        shutil.rmtree(sample_dir, onexc=lambda fn, path, exc: (os.chmod(path, stat.S_IWRITE), fn(path)))
    except TypeError:
        shutil.rmtree(sample_dir, onerror=remove_readonly)
os.makedirs(sample_dir, exist_ok=True)

def run_git(args, cwd=sample_dir):
    res = subprocess.run([mingit] + args, cwd=cwd, env=env, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Git command failed: {args}\nError: {res.stderr}")
    return res.stdout.strip()

print("Initializing git repository...")
run_git(["init"])
run_git(["config", "user.name", "Alice Dev"])
run_git(["config", "user.email", "alice@example.com"])

# --- Commit 1: Initial implementation ---
with open(os.path.join(sample_dir, "requirements.txt"), "w", encoding="utf-8") as f:
    f.write("pytest>=8.0.0\n")

cart_v1 = '''class ShoppingCart:
    def __init__(self, user_tier="standard"):
        self.user_tier = user_tier
        self.items = []

    def add_item(self, name: str, price: float, quantity: int = 1):
        if price < 0 or quantity <= 0:
            raise ValueError("Invalid price or quantity")
        self.items.append({"name": name, "price": float(price), "quantity": int(quantity)})

    def get_subtotal(self) -> float:
        return sum(item["price"] * item["quantity"] for item in self.items)
'''
with open(os.path.join(sample_dir, "cart.py"), "w", encoding="utf-8") as f:
    f.write(cart_v1)

test_v1 = '''import pytest
from cart import ShoppingCart

def test_add_item():
    cart = ShoppingCart()
    cart.add_item("Book", 15.0, 2)
    assert cart.get_subtotal() == 30.0
'''
with open(os.path.join(sample_dir, "test_cart.py"), "w", encoding="utf-8") as f:
    f.write(test_v1)

run_git(["add", "."])
run_git(["commit", "-m", "feat: Initial shopping cart implementation"])

# --- Commit 2: Add loyalty discount calculation (BUGGY COMMIT) ---
# Notice: LOYALTY_DISCOUNTS has bronze, silver, gold.
# But for standard user (or missing tier), LOYALTY_DISCOUNTS.get(self.user_tier) returns None!
# Then subtotal * discount_rate triggers TypeError: unsupported operand type(s) for *: 'float' and 'NoneType'
cart_v2 = '''LOYALTY_DISCOUNTS = {
    "bronze": 0.05,
    "silver": 0.10,
    "gold": 0.15,
}

class ShoppingCart:
    def __init__(self, user_tier="standard"):
        self.user_tier = user_tier
        self.items = []

    def add_item(self, name: str, price: float, quantity: int = 1):
        if price < 0 or quantity <= 0:
            raise ValueError("Invalid price or quantity")
        self.items.append({"name": name, "price": float(price), "quantity": int(quantity)})

    def get_subtotal(self) -> float:
        return sum(item["price"] * item["quantity"] for item in self.items)

    def calculate_total(self, tax_rate: float = 0.05) -> float:
        subtotal = self.get_subtotal()
        # Look up loyalty discount tier
        discount_rate = LOYALTY_DISCOUNTS.get(self.user_tier)
        discount_amount = subtotal * discount_rate
        tax_amount = (subtotal - discount_amount) * tax_rate
        return round((subtotal - discount_amount) + tax_amount, 2)
'''
with open(os.path.join(sample_dir, "cart.py"), "w", encoding="utf-8") as f:
    f.write(cart_v2)

run_git(["add", "cart.py"])
run_git(["commit", "-m", "feat: Add loyalty discount calculation"])

# --- Commit 3: Docs and refactoring ---
cart_v3 = '''"""Shopping Cart Module with Loyalty Discount Support."""

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
'''
with open(os.path.join(sample_dir, "cart.py"), "w", encoding="utf-8") as f:
    f.write(cart_v3)

run_git(["add", "cart.py"])
run_git(["commit", "-m", "docs: Add method docstrings and type annotations"])

# --- Commit 4: Add receipt formatting (Latest commit - innocent) ---
cart_v4 = '''"""Shopping Cart Module with Loyalty Discount Support."""

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
        return "\\n".join(lines)
'''
with open(os.path.join(sample_dir, "cart.py"), "w", encoding="utf-8") as f:
    f.write(cart_v4)

test_v4 = '''import pytest
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
'''
with open(os.path.join(sample_dir, "test_cart.py"), "w", encoding="utf-8") as f:
    f.write(test_v4)

run_git(["add", "cart.py", "test_cart.py"])
run_git(["commit", "-m", "feat: Add order receipt formatting and audit logging"])

print("Sample repo created successfully with 4 commits!")
print("Recent git log:")
print(run_git(["log", "--oneline"]))
