# 非交互模式将包含凭据的 nGQL 原样输出到标准输出

建议英文标题：**Non-interactive modes echo credential-bearing nGQL input to standard output**

## 披露信息

- 状态：保密期内，尚未公开披露
- 产品：Nebula Console
- 上游仓库：<https://github.com/vesoft-inc/nebula-console>
- 已验证版本：`master`，提交 `8ea370a0125cdb8f76a8e324aaaf1d2cb3ed051b`
- 验证日期：2026-08-16
- 报告人邮箱：`sss211717@gmail.com`
- 已确认受影响入口：`-e/--eval` 和 `-f/--file`
- 准确受影响发行版范围：等待上游确认
- 建议 CWE：CWE-201（主要）；stdout 被日志系统持久化时可补充 CWE-532
- 候选严重程度：在日志读取者与数据库管理员权限分离的场景下为中危
- 候选 CVSS v3.1：`5.0 (CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N)`

CVSS 仅供上游/CNA 讨论。严重程度取决于 stdout 是否被采集，以及读取 stdout 的主体是否无权获取数据库凭据。

## 漏洞概述

Nebula Console 把两个非交互输入来源 `-e/--eval` 和 `-f/--file` 都传递给同一个 `nCli` 实现，并固定设置 `output=true`。`nCli.ReadLine` 在执行每一行输入之前，会无条件把原始内容写入 stdout。

因此，以下 nGQL 会把完整密码复制到标准输出：

```ngql
CREATE USER example WITH PASSWORD 'secret';
```

在自动化或运维环境中，stdout 通常会被 CI 系统、容器运行时、服务日志、终端审计或集中日志平台持久化。这些系统的可读人员范围和保存周期可能大于原始 nGQL 输入。

`-e` 和 `-f` 只是两个输入来源，最终使用同一个输出点和同一个修复点，因此作为一个漏洞报告。

## 根因分析

以下行号基于已验证提交：

- `main.go:445-446`：定义 `-e` 和 `-f`。
- `main.go:465-466`：定义对应长参数别名。
- `main.go:607-608`：`-e` 使用 `output=true` 创建 `nCli`。
- `main.go:609-614`：`-f` 使用同一个 `nCli`，同样固定为 `output=true`。
- `cli/ncli.go:60-68`：通过默认写入 stdout 的 `fmt.Print` 和 `fmt.Println` 输出原始输入。

关键输出点：

```go
if l.output {
    fmt.Print(l.status.nebulaPrompt())
    fmt.Println(input)
}
```

同一个 `output` 属性还通过 `nCli.Output` 和 `main.go:367-371` 控制正常执行结果是否显示。因此，简单地向 `NewnCli` 传递 `false` 会同时关闭危险的输入回显和正常结果输出。输入回显与结果显示需要拆分为独立控制项。

## 动态验证结果

验证使用一次性 NebulaGraph 测试服务、由上述提交编译的客户端、唯一测试用户和虚假密码标记。

验证结果：

1. `-e` 模式执行有效 `CREATE USER` 时，虚假密码标记在 stdout 中出现一次。
2. `-f` 模式执行普通 nGQL 文件时，另一虚假密码标记在 stdout 中出现一次。
3. 两个测试账户均在验证后立即删除。
4. 未使用生产凭据，也未读取无关数据库数据。

## 复现步骤

请仅在一次性测试环境中使用虚假凭据。下面的管理员密码占位符不得替换为生产凭据。

```bash
TEST_DIR="$(mktemp -d)"
umask 0077

CONSOLE=./nebula-console
TEST_ADDR=127.0.0.1
TEST_PORT=9669
TEST_USER=test_admin
TEST_PASSWORD='<DISPOSABLE_ADMIN_PASSWORD>'
```

### `-e/--eval`

```bash
"$CONSOLE" \
  -addr "$TEST_ADDR" \
  -P "$TEST_PORT" \
  -u "$TEST_USER" \
  -p "$TEST_PASSWORD" \
  -e "CREATE USER out_e_probe WITH PASSWORD 'STDOUT_E_TEST_ONLY_5a2c91';" \
  >"$TEST_DIR/e.stdout" 2>"$TEST_DIR/e.stderr"

grep -F 'STDOUT_E_TEST_ONLY_5a2c91' "$TEST_DIR/e.stdout"
```

### `-f/--file`

```bash
printf '%s\n' \
  "CREATE USER out_f_probe WITH PASSWORD 'STDOUT_F_TEST_ONLY_6b3d82';" \
  >"$TEST_DIR/probe.ngql"

"$CONSOLE" \
  -addr "$TEST_ADDR" \
  -P "$TEST_PORT" \
  -u "$TEST_USER" \
  -p "$TEST_PASSWORD" \
  -f "$TEST_DIR/probe.ngql" \
  >"$TEST_DIR/f.stdout" 2>"$TEST_DIR/f.stderr"

grep -F 'STDOUT_F_TEST_ONLY_6b3d82' "$TEST_DIR/f.stdout"
```

收集测试证据后，应删除两个一次性测试用户和临时目录。

### 实际结果

两个 stdout 文件都包含完整输入语句以及其中的虚假密码，并且该内容出现在正常执行结果之前。

### 预期结果

非交互执行应显示查询执行结果，但不应重现包含凭据的原始输入。原始输入回显应默认关闭，或者必须由用户通过明确且有风险说明的选项主动启用。

## 安全影响

nGQL 中的密码可能被复制到访问权限和保存周期不同于原始输入的系统，例如：

- CI/CD 作业日志和可下载构建产物
- Kubernetes 或其他容器运行时日志
- 服务日志、systemd journal 和进程管理器
- 集中日志与可观测平台
- 终端录制和会话审计系统

对于 `-f`，源脚本本身已经存在，但 stdout 回显会主动创建额外副本，该副本可能保存更久或允许更多人员读取。

典型权限边界是：数据库管理员负责提供 nGQL，而低权限构建人员、支持人员或日志读取角色能够查看采集的 stdout，但没有权限知道数据库账户密码。

影响成立需要输入包含敏感值，并且存在能够读取 stdout 副本但无权获得这些凭据的主体。本报告不主张程序直接将密码发送给未认证远程攻击者。

## 修复建议

1. 把原始输入回显和执行结果显示拆分为独立控制项，例如 `echoInput` 与 `showResults`。
2. `-e` 和 `-f` 默认继续显示执行结果，但默认关闭原始输入回显。
3. 如果兼容性要求保留回显，提供类似 `--echo-input` 的显式选项，并清楚说明不得与敏感语句一起使用。
4. 如果增加脱敏作为纵深防御，应使用理解 nGQL 的解析器或分词器，避免依赖脆弱的大小写敏感正则表达式。
5. 复核错误输出路径，避免删除当前直接回显后，又由错误消息重新输出完整敏感语句。
6. 为 `-e`、`-f`、多行语句、执行失败以及大小写/空白变体增加 stdout 捕获测试，确保执行结果仍显示而敏感输入不显示。
7. 在安全公告中提供受影响日志清理和凭据轮换指导。

## 范围说明

- `-e` 输入还会出现在进程参数，并可能进入 Shell 历史和操作系统审计数据。这属于独立的命令行或部署风险，明确不在本报告范围内。
- 本报告不主张 `-f` 导致源脚本文件产生，也不讨论该源文件权限；本报告关注 Nebula Console 主动创建的额外 stdout 副本。
- 默认交互模式的 `.nebula_history` 行为由另一份报告单独说明。
- 本报告不把正常查询结果视为漏洞，只讨论程序无条件重现查询输入本身。
- 终端录制和日志采集会放大影响，是否形成未授权泄露取决于实际部署的访问控制。

## 参考

- 上游安全策略：<https://github.com/vesoft-inc/nebula-console/security/policy>
- CWE-201：<https://cwe.mitre.org/data/definitions/201.html>
- CWE-532：<https://cwe.mitre.org/data/definitions/532.html>
