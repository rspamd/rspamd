from robot.libraries.BuiltIn import BuiltIn

def Apply_Grow_Factor(grow_factor, max_limit):
    grow_factor = float(grow_factor)
    max_limit = float(max_limit)
    expected_result = {}
    res = BuiltIn().get_variable_value("${SCAN_RESULT}")

    for sym, p in res["symbols"].items():
        expected_result[sym] = p["score"]

    if grow_factor <= 1.0:
        return expected_result

    if max_limit <= 0:
        return expected_result

    final_grow_factor = grow_factor
    mult = grow_factor - 1.0
    for sym, p in res["symbols"].items():
        if p["score"] <= 0:
            continue
        mult *= round(p["score"] / max_limit, 2)
        final_grow_factor *= round(1.0 + mult, 2)

    if final_grow_factor <= 1.0:
        return expected_result

    for sym, p in res["symbols"].items():
        if p["score"] <= 0:
            continue
        expected_result[sym] = round(p["score"] * final_grow_factor, 2)
