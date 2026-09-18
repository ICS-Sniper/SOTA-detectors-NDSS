import struct
import re


def to_float(vars):
    if vars[0] is None:
        return None
    try:
        return struct.unpack("<f", bytes.fromhex(vars[0]))[0]
    except (struct.error, ValueError):
        return None


def to_int(vars):
    if vars[0] is None:
        return None
    try:
        return struct.unpack("<h", bytes.fromhex(vars[0]))[0]
    except (struct.error, ValueError):
        return None


def to_bool(vars):
    """Convert to boolean for status fields that might be 0/1"""
    if vars[0] is None:
        return None
    try:
        val = struct.unpack("<h", bytes.fromhex(vars[0]))[0]
        return bool(val)
    except (struct.error, ValueError):
        return None


JS = {
    "protocols": ["cip"],
    "rename": {
        "10.8.0.4:44818": "SCADA",
        "10.8.0.5:.*": "PLC",
    },
    "rules": [
        {
            "type": "76",
            "var": [".*AIT.*_Pv"],
            "method": to_float,
            "name": "analog_temp_pv",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*FIT.*_Pv"],
            "method": to_float,
            "name": "flow_pv",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*LIT.*_Pv"],
            "method": to_float,
            "name": "level_pv",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*DPIT.*_Pv"],
            "method": to_float,
            "name": "diff_pressure_pv",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*P[0-9]+_Status"],
            "method": to_int,
            "name": "pump_status",
            "remove": False,
        },
        {
            "type": "76", 
            "var": [".*MV[0-9]+_Status"],
            "method": to_int,
            "name": "valve_status",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*UV[0-9]+_Status"],
            "method": to_int,
            "name": "uv_status",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*P[1-6]_State"],
            "method": to_int,
            "name": "process_state",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*LS.*_Alarm"],
            "method": to_bool,
            "name": "level_alarm",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*PSH.*_Alarm"],
            "method": to_bool,
            "name": "pressure_alarm",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*DPSH.*_Alarm"],
            "method": to_bool,
            "name": "diff_pressure_alarm",
            "remove": False,
        },
        {
            "type": "77",
            "var": [".*_Status"],
            "method": to_int,
            "name": "command_status",
            "remove": False,
        },
        {
            "type": "77",
            "var": [".*_State"],
            "method": to_int,
            "name": "command_state",
            "remove": False,
        },
        {
            "type": "76",
            "var": [".*"],  # Catch-all
            "method": to_float,  # Default to float for unknown sensors
            "name": "unknown_sensor",
            "remove": False,
        },
    ],
}
