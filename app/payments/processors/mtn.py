def generate_mtn_payment_link(amount, merchant_code, order_id):
    return f"*165*3*{merchant_code}*{amount}*{order_id}%23"