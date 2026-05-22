RED_BOLD = "\033[1;31m"
ORANGE_BOLD = "\033[1;33m"
GREEN = "\033[0;32m"
NO_COLOR = ""
COLOR_END = "\033[m"


def get_color(level):
    if level <= 3:  # Error and higher
        return RED_BOLD
    elif level == 4:  # Warning
        return ORANGE_BOLD
    elif level <= 7:  # Info
        return NO_COLOR
    else:  # Other
        return GREEN


TS_MIN_LEN = 12


def get_ts(ts):
    ts = ts[:-6] + "." + ts[-6:]
    ts = ts.rjust(TS_MIN_LEN)
    return f"[{ts}] "


while True:
    line = input()
    try:
        level, _seq_num, ts, *msg = line.split(",")
    except:
        print(line)
        continue
    level = int(level)
    msg = "".join(msg)
    msg = msg[msg.find(";") + 1:]
    new_line = get_color(level) + get_ts(ts) + msg + COLOR_END
    print(new_line)
