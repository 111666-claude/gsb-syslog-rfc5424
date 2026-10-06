"""固定场景，用来复现题面里的锚点。"""

import json

from . import core

BASE = "<165>1 2003-10-11T22:14:15.003Z %s app 1234 ID47 %s message"


def _line(obj):
    print(json.dumps(obj, ensure_ascii=False))


def run(name):
    if name == "pri":
        parsed = core.parse_line(BASE % ("host", "-"), core.Counter())
        _line({"facility": parsed["facility"], "severity": parsed["severity"]})
        return 0
    if name == "nil":
        parsed = core.parse_line(BASE % ("-", "-"), core.Counter())
        _line({"hostname": parsed["hostname"]})
        return 0
    if name == "esc":
        line = BASE % ("host", '[ex a="x\\]y"]')
        parsed = core.parse_line(line, core.Counter())
        _line({"param": parsed["sd"]["ex"]["a"]})
        return 0
    if name == "dup":
        store = core.Store(10)
        line = BASE % ("host", "-")
        first = store.feed(line, 0, core.Counter())
        second = store.feed(line, 0, core.Counter())
        _line({"accepted": int(first is not None) + int(second is not None)})
        return 0
    if name == "work":
        store = core.Store(10)
        counter = core.Counter()
        for i in range(2000):
            line = BASE % ("host", "-") + " m%04d" % i
            line = line.replace("ID47", "ID%04d" % i)
            store.feed(line, 0, counter)
        _line({"messages": 2000, "scanned": counter.scanned})
        return 0
    raise SystemExit("未知场景：" + name)
