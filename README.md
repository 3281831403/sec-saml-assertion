单点登录接进来之后，把断言里的受众改一改，别的系统照样能拿它登录进来：规范化只排序属性不排序命名空间声明，同一文档两种字节表示；规范化把空元素写成开闭标签对，与标准实现不一致；签名引用解析取第一个同名节点，重复 ID 时可被替换；验签只覆盖断言主体不覆盖条件节点，改时间不影响签名；有效期判定用闭合区间但偏移量在两端各加一次，窗口被放大一倍；有效期不校验签发时间不能晚于当前时间，未来断言可用；受众判定用前缀比较，子域被放行；主体确认只比较名称不比较格式，格式不同但同值被判不等；重放缓存只按 ID 记录不按签发者分区，同一 ID 跨签发者冲突；批量校验复用规范化结果，第二个文档沿用第一个文档的字节。engine/sso/assertion.py 是核心，tests/sso/test_assertion.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```
python -m pytest tests -q
```

预期输出恰好为 `15 failed`，且没有 `error`。`tests/sso/test_assertion.py` 不可修改，验收以其中现有的 15 个测试为准。

## 字段

| 字段 | 值 |
| --- | --- |
| 难度 | 明显偏难 |
| 领域 | 安全 |
| 能力 | 漏洞检测与攻防 |
| 类型 | Bugfix |
| 技术栈 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

## 目录与布局

```
sec-saml-assertion/
  README.md
  conftest.py
  engine/__init__.py
  engine/sso/__init__.py
  engine/sso/assertion.py
  tests/sso/test_assertion.py
```

实现采用 `engine` 嵌套布局：核心代码位于 `engine/sso/assertion.py`，测试位于 `tests/sso/test_assertion.py`。根目录 `conftest.py` 把仓库根加入 `sys.path`，因此从根目录运行 pytest 时可直接导入 `engine.sso.assertion`，不需要安装包，也不访问网络。

`engine/sso/assertion.py` 提供八个函数：`canonicalize`、`signed_nodes`、`verify_signature`、`check_conditions`、`check_audience`、`check_subject`、`replay_guard`、`assertion_batch`。需要修复的十个缺陷全部位于这八个函数的实现中，测试从规范化字节、签名覆盖节点、时间边界和重放缓存行为等角度严格约束契约。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

