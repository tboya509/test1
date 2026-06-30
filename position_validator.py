"""
Position Sizing Validator
Ensures position sizes fit within available margin and risk limits
"""

import logging
from typing import Tuple, Optional
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Position:
    symbol: str
    quantity: int
    instrument_type: str  # 'EQUITY' or 'OPTIONS'
    entry_price: float
    portfolio_value: float = 100000  # ₹1L default


class PositionValidator:
    """Validate position sizes before execution"""

    def __init__(self, total_capital: float = 100000, risk_percent: float = 1.0, margin_buffer: float = 0.2):
        """
        Args:
            total_capital: Total trading capital (₹)
            risk_percent: Risk per trade as % of capital
            margin_buffer: Keep this % of margin as buffer (default 20%)
        """
        self.total_capital = total_capital
        self.risk_percent = risk_percent
        self.margin_buffer = margin_buffer
        self.max_positions = 3
        self.current_positions = []

    def get_margin_requirement(self, symbol: str, quantity: int, instrument_type: str, price: float) -> float:
        """
        Calculate margin requirement for NSE/NFO instruments
        
        Margin structure (approximate):
        - EQUITY MIS: 10-15% of notional value
        - OPTIONS: 10-20% of notional value (depends on Greeks)
        - BANKNIFTY: 4x lot = 140 qty
        - NIFTY: 4x lot = 300 qty
        """
        notional_value = quantity * price

        if instrument_type == "EQUITY":
            # Equity MIS: ~12% margin
            return notional_value * 0.12
        elif instrument_type == "OPTIONS":
            # Options: ~15% margin (conservative estimate)
            return notional_value * 0.15
        else:
            return notional_value * 0.10

    def get_available_margin(self, current_margin_used: float) -> float:
        """Calculate available margin from total capital"""
        return self.total_capital - current_margin_used

    def validate_position_size(
        self,
        symbol: str,
        quantity: int,
        instrument_type: str,
        price: float,
        current_margin_used: float = 0,
        current_open_positions: int = 0
    ) -> Tuple[bool, str, Optional[int]]:
        """
        Validate if position can be executed
        
        Returns:
            (is_valid, reason, adjusted_quantity)
        """
        
        # 1. Check max positions limit
        if current_open_positions >= self.max_positions:
            return False, f"Max positions limit reached ({self.max_positions})", None

        # 2. Calculate required margin
        required_margin = self.get_margin_requirement(symbol, quantity, instrument_type, price)
        available_margin = self.get_available_margin(current_margin_used)

        # 3. Apply buffer (keep 20% as safety cushion)
        max_usable_margin = available_margin * (1 - self.margin_buffer)

        if required_margin > max_usable_margin:
            # Try to reduce quantity
            adjusted_qty = int((max_usable_margin / self.get_margin_requirement(symbol, 1, instrument_type, price)))
            
            if adjusted_qty >= 1:
                logger.warning(
                    f"Position size reduced for {symbol}: {quantity} → {adjusted_qty} "
                    f"(Required: ₹{required_margin:.0f}, Available: ₹{max_usable_margin:.0f})"
                )
                return True, f"Quantity auto-reduced to {adjusted_qty}", adjusted_qty
            else:
                return False, (
                    f"Insufficient margin: Required ₹{required_margin:.0f}, "
                    f"Available ₹{max_usable_margin:.0f} (after {int(self.margin_buffer*100)}% buffer)"
                ), None

        # 4. Risk-per-trade check (1% risk rule)
        max_risk_rupees = self.total_capital * (self.risk_percent / 100)
        
        # For equity: assume 2% stop loss
        # For options: assume 50% max loss (premium paid)
        if instrument_type == "EQUITY":
            stop_loss_pct = 0.02
            position_risk = quantity * price * stop_loss_pct
        elif instrument_type == "OPTIONS":
            position_risk = quantity * price * 0.5  # Assume lose 50% of premium
        else:
            position_risk = 0

        if position_risk > max_risk_rupees:
            return False, (
                f"Exceeds 1% risk rule: Position risk ₹{position_risk:.0f} > "
                f"Max allowed ₹{max_risk_rupees:.0f}"
            ), None

        # 5. Minimum quantity check
        min_qty = {
            "EQUITY": 1,
            "BANKNIFTY": 35,
            "NIFTY": 75,
            "OPTIONS": 1
        }
        
        min_required = min_qty.get(instrument_type, 1)
        if quantity < min_required:
            return False, f"Quantity {quantity} below minimum {min_required}", None

        # All checks passed
        logger.info(
            f"✅ Position valid: {symbol} x{quantity} | Margin: ₹{required_margin:.0f} | "
            f"Available: ₹{available_margin:.0f}"
        )
        return True, "Position valid", quantity

    def add_position(self, position: Position) -> bool:
        """Track position after execution"""
        if len(self.current_positions) < self.max_positions:
            self.current_positions.append(position)
            logger.info(f"Position added: {position.symbol} x{position.quantity}")
            return True
        return False

    def remove_position(self, symbol: str) -> bool:
        """Remove position after close"""
        self.current_positions = [p for p in self.current_positions if p.symbol != symbol]
        logger.info(f"Position removed: {symbol}")
        return True

    def get_portfolio_margin_usage(self) -> Tuple[float, float, float]:
        """
        Returns (total_margin_used, margin_available, margin_usage_percent)
        """
        total_margin_used = sum(
            self.get_margin_requirement(p.symbol, p.quantity, p.instrument_type, p.entry_price)
            for p in self.current_positions
        )
        available = self.total_capital - total_margin_used
        usage_pct = (total_margin_used / self.total_capital) * 100
        return total_margin_used, available, usage_pct

    def get_summary(self) -> dict:
        """Return position summary"""
        margin_used, margin_available, usage_pct = self.get_portfolio_margin_usage()
        return {
            "total_capital": self.total_capital,
            "margin_used": margin_used,
            "margin_available": margin_available,
            "margin_usage_percent": usage_pct,
            "open_positions": len(self.current_positions),
            "max_positions": self.max_positions,
            "positions": [
                {
                    "symbol": p.symbol,
                    "qty": p.quantity,
                    "type": p.instrument_type,
                    "entry": p.entry_price
                }
                for p in self.current_positions
            ]
        }


if __name__ == "__main__":
    # Example usage
    logging.basicConfig(level=logging.INFO)
    
    validator = PositionValidator(total_capital=100000)
    
    # Test 1: Valid NIFTY options position
    is_valid, msg, adj_qty = validator.validate_position_size(
        symbol="NIFTY25JUN21100CE",
        quantity=75,
        instrument_type="OPTIONS",
        price=150,
        current_margin_used=5000,
        current_open_positions=1
    )
    print(f"Test 1 (NIFTY 75 lot): {is_valid} - {msg} (Qty: {adj_qty})")
    
    # Test 2: Valid BANKNIFTY position
    is_valid, msg, adj_qty = validator.validate_position_size(
        symbol="BANKNIFTY25JUN48000CE",
        quantity=35,
        instrument_type="OPTIONS",
        price=200,
        current_margin_used=5000,
        current_open_positions=1
    )
    print(f"Test 2 (BANKNIFTY 35 lot): {is_valid} - {msg} (Qty: {adj_qty})")
    
    # Test 3: Equity position (should reduce qty if margin insufficient)
    is_valid, msg, adj_qty = validator.validate_position_size(
        symbol="INFY",
        quantity=500,
        instrument_type="EQUITY",
        price=1200,
        current_margin_used=50000,
        current_open_positions=2
    )
    print(f"Test 3 (INFY 500): {is_valid} - {msg} (Qty: {adj_qty})")
    
    print("\n" + "="*50)
    print(validator.get_summary())
