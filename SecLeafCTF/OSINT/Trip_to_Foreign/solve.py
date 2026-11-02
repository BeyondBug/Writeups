#!/usr/bin/env python3

# Office Navi Building Code for Yoyogi Park ONE BLDG
bldg_code = "02057170"

# Parking fee: 2 vehicles for 12 hours (Harvest Moon September rate: 2,400 JPY cap)
parking_fee = 2 * 2400

print(f"Building Code: {bldg_code}")
print(f"Parking Fee in Yen: {parking_fee}")
print(f"Flag: CRY{{{bldg_code}_{parking_fee}}}")
