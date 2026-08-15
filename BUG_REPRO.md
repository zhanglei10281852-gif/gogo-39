# Bug Reproduction

## 包的性质

当前 test_model_fix 保存的是被测模型修复后的结果源码，不是初始含 Bug 源码。要复现原始缺陷，必须检出下面固定的 parent SHA；不要在当前修复结果源码上期待重新出现修复前失败。生成系统使用的可信验证补丁和完整验证日志仅在本地留存，不提交到结果分支。

## 问题现象

请求里的 tool call arguments 明明是 null，Validate 却返回成功，后续策略把它当成有效工具调用继续评估；接口契约要求 arguments 必须是 JSON object。请先调查，暂时不要修改代码。请定位具体 Go 文件和符号，解释 null 如何通过解码和校验，并给出可核验证据。先不要改仓库代码。

## 含 Bug 版本

- 仓库：zhanglei10281852-gif/gogo-39
- 仓库地址：https://github.com/zhanglei10281852-gif/gogo-39.git
- parent SHA：3dedd4cf9211d09f702b19b12c2ebfdc4e966e02

## 复现步骤

```bash
git clone -- https://github.com/zhanglei10281852-gif/gogo-39.git bug-repro
cd bug-repro
git checkout --detach 3dedd4cf9211d09f702b19b12c2ebfdc4e966e02
go test ./model -run "^TestToolCallValidateRejectsNullArguments$" -count=1 -v
```

## 双架构完整错误信息

### linux/amd64

- 容器内复现预期退出码：1
- 容器内复现实际退出码：1

stdout：

```text
$ go test ./model -run "^TestToolCallValidateRejectsNullArguments$" -count=1 -v
=== RUN   TestToolCallValidateRejectsNullArguments
    model_test.go:18: ToolCall.Validate() error = nil, want validation error for null arguments
--- FAIL: TestToolCallValidateRejectsNullArguments (0.00s)
FAIL
FAIL	agentguard/model	0.002s
FAIL

```

stderr：

```text
(empty)
```

### linux/arm64

- 容器内复现预期退出码：1
- 容器内复现实际退出码：1

stdout：

```text
$ go test ./model -run "^TestToolCallValidateRejectsNullArguments$" -count=1 -v
=== RUN   TestToolCallValidateRejectsNullArguments
    model_test.go:18: ToolCall.Validate() error = nil, want validation error for null arguments
--- FAIL: TestToolCallValidateRejectsNullArguments (0.01s)
FAIL
FAIL	agentguard/model	0.127s
FAIL

```

stderr：

```text
(empty)
```

## 通过条件

定位 model/model.go 的 ToolCall.Validate；解释 RawMessage null 解码为 nil map 且 json.Unmarshal 不报错、仅检查 err 导致放行的完整机制；有证据且目标仓库零改动。
