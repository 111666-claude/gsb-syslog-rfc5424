# syslog-rfc5424

解析 RFC5424 syslog 行：优先级拆设施与严重度、NILVALUE、结构化数据转义，以及窗口内去重。只用 Python 标准库。

```
python3 -m unittest discover -s tests
python3 -m syslog5424 --sample=pri
python3 -m syslog5424 --sample=nil
python3 -m syslog5424 --sample=esc
python3 -m syslog5424 --sample=dup
python3 -m syslog5424 --sample=work
```

## 口径

- **优先级**：`<PRI>` 拆成设施 `PRI // 8` 与严重度 `PRI % 8`。
- **NILVALUE**：字段值为 `-` 时表示缺失，解析成空串；结构化数据为 `-` 时表示没有。
- **转义**：结构化数据参数里的 `\"`、`\\`、`\]` 还原成对应的单字符。
- **去重**：同一来源、同一应用、同一消息标识与同一正文的消息，在窗口内重复出现只算一次。

## 不变量

- 解析结果的设施小于 24、严重度小于 8。
- 结构化数据参数值里不含转义用的反斜杠。
- `scanned` 不随消息数平方级放大：两千条消息的 `scanned` 不超过 6000。

## 输出契约

解析结果是一个字段字典（`pri` / `facility` / `severity` / `version` / `hostname` / `app` / `msgid` / `sd` / `msg`）；
窗口内重复的消息返回 `None`。场景打印一行 JSON。`--sample=work` 打印 `{"messages": N, "scanned": N}`。
