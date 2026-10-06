"""syslog 行解析与窗口去重。"""


class Counter:
    """记录比较次数。"""

    def __init__(self):
        self.scanned = 0


def _parse_sd(text, counter):
    sd = {}
    i = 0
    while i < len(text) and text[i] == "[":
        i += 1
        start = i
        while i < len(text) and text[i] not in " ]":
            i += 1
        sid = text[start:i]
        params = {}
        while i < len(text) and text[i] != "]":
            while i < len(text) and text[i] == " ":
                i += 1
            if i < len(text) and text[i] == "]":
                break
            pstart = i
            while i < len(text) and text[i] != "=":
                i += 1
            pname = text[pstart:i]
            i += 1
            if i < len(text) and text[i] == '"':
                i += 1
                buf = []
                while i < len(text) and text[i] != '"':
                    if text[i] == "\\" and i + 1 < len(text) and text[i + 1] in '"\\]':
                        buf.append(text[i + 1])
                        i += 2
                    else:
                        buf.append(text[i])
                        i += 1
                i += 1
                params[pname] = "".join(buf)
            else:
                vstart = i
                while i < len(text) and text[i] not in " ]":
                    i += 1
                params[pname] = text[vstart:i]
        if i < len(text) and text[i] == "]":
            i += 1
        sd[sid] = params
        counter.scanned += 1
    return sd, text[i:]


def parse_line(line, counter):
    counter.scanned += 1
    line = line.strip()
    if not line.startswith("<"):
        return None
    end = line.find(">")
    if end < 0:
        return None
    try:
        pri = int(line[1:end])
    except ValueError:
        return None
    tokens = line[end + 1:].split(" ", 6)
    if len(tokens) < 7:
        return None
    version, _ts, host, app, _procid, msgid, rest = tokens
    host = "" if host == "-" else host
    app = "" if app == "-" else app
    msgid = "" if msgid == "-" else msgid
    if rest.startswith("["):
        sd, msg = _parse_sd(rest, counter)
    elif rest.startswith("-"):
        sd = {}
        msg = rest[1:].lstrip(" ")
    else:
        sd = {}
        msg = rest
    return {
        "pri": pri,
        "facility": pri // 8,
        "severity": pri % 8,
        "version": version,
        "hostname": host,
        "app": app,
        "msgid": msgid,
        "sd": sd,
        "msg": msg,
    }


class Store:
    def __init__(self, window):
        self.window = window
        self.seen = {}

    def feed(self, line, now, counter):
        parsed = parse_line(line, counter)
        if parsed is None:
            return None
        ident = (parsed["hostname"], parsed["app"], parsed["msgid"], parsed["msg"])
        counter.scanned += 1
        last = self.seen.get(ident)
        if last is not None and now - last <= self.window:
            return None
        self.seen[ident] = now
        return parsed
