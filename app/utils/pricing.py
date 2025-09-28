def calculate_price(pages, copies, paper_type, paper_size, color, priority):
    base_price = 200  # UGX per page
    
    multipliers = {
        "paper_type": {
            "Plain Paper": 1.0,
            "Art Paper": 2.5,
            "Art Board": 3.0
        },
        "paper_size": {
            "A3": 5.0,
            "A4": 1.0,
            "A5": 1.25,
            "Other": 1.0
        },
        "priority": {
            'Normal': 1.0,
            'High': 1.5,
            'Rush': 2.0
        }
    }
    
    total = base_price * pages * copies
    total *= multipliers["paper_type"].get(paper_type, 1.0)
    total *= multipliers["paper_size"].get(paper_size, 1.0)
    total *= 2.5 if color else 1.0
    total *= multipliers["priority"].get(priority, 1.0)
    
    return total