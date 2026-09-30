# tagwatch

**給有 MTE 的 Apple Silicon Mac 用的資料監看點（watchpoint）：數量不限、精細到 16 位元組。**

硬體監看點可以回答「是誰動了這塊記憶體？」，可是 CPU 只有 4 個。用 `mprotect` 保護整個分頁沒有數量限制，但同一個
16 KB 分頁裡的任何存取都會被攔下來。tagwatch 改用 ARM 的記憶體標記延伸功能（Memory Tagging Extension，M5 之後的
晶片才有）：把要監看的記憶體換成一個「程式裡沒有任何指標帶著」的標籤，於是只有碰到這塊記憶體的存取會出錯。每一次
存取都會被記錄下來（位址、寬度、讀或寫、執行緒、呼叫堆疊），然後放行，記憶體繼續被監看。可以只看一個欄位，也可以
一次看某種物件的每一個實體。

[English](README.md) · [設計筆記（英文）](docs/DESIGN.md) · [效能量測方法與原始輸出（英文）](docs/BENCHMARKS.md) ·
[導讀（給初學者）](docs/導讀.zh-TW.md)

```
$ tagwatch run -w -a caller=customer_new,off=16,len=8,label=credit_limit -- ./ledger
```

意思是：執行 `./ledger`，凡是 `customer_new` 配置出來的堆積物件，第 16–23 個位元組每被**寫入**一次就回報一次。

## 實際找一個 bug

[`examples/ledger.c`](examples/ledger.c) 有 500 筆客戶資料，每筆是 16 位元組的暱稱，後面接信用額度。有一個函式
複製暱稱時沒檢查長度，暱稱太長就會蓋到**同一個堆積物件裡**的信用額度。程式不會當掉，只有最後的稽核發現 5 筆額度
不對：

```
$ build/examples/ledger
ledger: 500 customers, 6713 charges declined
ledger: AUDIT FAILED: 5 customers have a credit limit other than 5000 (first: #96, limit 13881)
```

這種 bug 一般工具抓不到。AddressSanitizer 和 MTE 本身檢查的是一塊配置的**邊界**，而這次寫入從頭到尾沒有越過邊界。
除錯器的監看點需要一個位址，可是事先不知道 500 個物件裡哪 5 個會中獎。用 tagwatch 就把每個物件的那個欄位都監看起來，
再問是誰寫的（`-q` 只印總結，`-w` 只回報寫入）：

```
$ build/tagwatch run -q -w -a caller=customer_new,off=16,len=8,label=credit_limit -- build/examples/ledger
ledger: 500 customers, 6713 charges declined
ledger: AUDIT FAILED: 5 customers have a credit limit other than 5000 (first: #96, limit 13881)

== tagwatch summary ==
program    /path/to/tagwatch/build/examples/ledger (pid 25002)
accesses   519 reported: 0 read, 519 write, 0 read-modify-write
watches    500 armed, 500 still armed at exit
threads    1
traps      34307 taken (33788 not reported: filtered or granule neighbours; 0 via the slow return path; 0 LL/SC emulated); 6 execution slots

Watched objects
  500 objects, 8 bytes each "credit_limit", allocated by customer_new+0x18 (ledger)
        0 reads, 519 writes
        busiest: #194 (5) #291 (5) #388 (5) #485 (5) #97 (4) #1 (1)

Access sites, busiest first
       500  write 16 bytes  500 watches ("credit_limit", ...)  offset +0
              customer_new+0x24 (ledger)
              import_customers+0x7c (ledger)
              main+0x20 (ledger)
              start+0x1a20 (dyld)
        19  write 1 byte  5 watches ("credit_limit", ...)  offsets +0..+3
              _platform_memmove+0x1c0 (libsystem_platform.dylib)
              set_nick+0x2c (ledger)
              import_customers+0xa4 (ledger)
              main+0x20 (ledger)
              start+0x1a20 (dyld)
```

寫這個欄位的地方只有兩處。一處是建構函式，每個物件一次。另一處是從 `set_nick` 呼叫的逐位元組 `memmove`，打中 5 個
物件：這就是 bug，連呼叫路徑都有了。「traps … not reported」那一行是 16 位元組粒度的代價：隔壁的 `balance` 欄位
和 `credit_limit` 在同一個粒度（granule）裡，所以存取它也會被攔下來，再依位址濾掉。

## 需求與限制（先講清楚）

| | |
| --- | --- |
| 硬體 | CPU 有 MTE 的 Mac：**M5 或更新**。`sysctl hw.optional.arm.FEAT_MTE` 要印出 1。 |
| 作業系統 | 只在 **macOS 27.0 (26A428)** 開發與測試過。macOS 26 沒測。 |
| 權限 | 不需要。不用 root、不用關 SIP、不用開開發者模式。 |
| 私有介面 | `tagwatch run` 用 `posix_spawnattr_set_use_sec_transition_shims_np` 幫子行程開 MTE，這是 libsystem 裡沒公開文件的 SPI（LLDB 的 `process launch --memory-tagging` 用的是同一個呼叫）。Apple 隨時可能改掉。 |
| 靠「被除錯」才能復原 | 在 macOS 上，標籤檢查錯誤會直接殺掉行程，除非它正被追蹤（ptrace）。所以目標程式會呼叫 `ptrace(PT_TRACE_ME)`，由 tagwatch 當它的追蹤者。一個行程只能有一個追蹤者，所以 LLDB 不能再附加上去；每收到一個訊號也會先短暫停住（見「限制」）。 |
| 粒度 | MTE 的標籤以 16 位元組為單位。tagwatch 的**回報**精確到位元組（依位址過濾），但同一個粒度裡的每次存取都要付一次攔截的成本。 |
| 成本 | 在 M5 上每次被攔下的存取大約 **5 微秒**（完整記錄時 7–8 微秒），沒被攔的存取是 0.1 奈秒。監看很熱的記憶體會很慢，見「量測」。 |
| 不能追蹤的對象 | 開了 hardened runtime 的程式、受 SIP 保護的系統程式（它們會忽略 `DYLD_INSERT_LIBRARIES`；tagwatch 會告訴你，程式照常執行但沒被監看）、arm64e 程式（執行期函式庫只有 arm64 版；未測試）、已經在執行的行程（沒有 attach 功能）。 |

`tagwatch check` 會在你的機器上把這些都檢查一遍，包含實際設一個監看點跑一次：

```
$ build/tagwatch check
CPU has MTE (hw.optional.arm.FEAT_MTE)      yes
spawn SPI to enable MTE in a child          yes
libtagwatch.dylib                           ./build/libtagwatch.dylib
end-to-end self test (watch, trap, resume)  passed
tagwatch can be used on this machine.
```

## 編譯

```sh
make            # build/tagwatch、build/libtagwatch.dylib、build/examples/ledger
make test       # 單元測試到處都能跑；MTE 測試只在有 MTE 的機器跑，其他機器會說明原因後略過
```

只需要 Xcode Command Line Tools（開發時用 Apple clang 17），沒有其他相依套件。

## 命令列用法

```
tagwatch run [選項] -- 程式 [參數...]

  -a, --watch-alloc SPEC        依大小和/或配置它的函式，監看堆積物件
  -s, --watch-symbol NAME[:LEN] 監看全域變數
  -x, --watch-addr ADDR:LEN     監看一段位址（搭配 --no-aslr）
  -w, --writes-only             只回報寫入
  -t, --trace FILE              保留 JSON-lines 追蹤檔
  -l, --log FILE / -q           即時記錄寫到檔案／不要即時記錄
      --heatmap                 總結裡加上各位移的熱度圖
      --depth N, --max-events N, --quarantine BYTES, --top N, --frames N, --no-summary, -v
```

完整清單看 `tagwatch --help`。配置規格用逗號組合：

| 規格 | 監看什麼 |
| --- | --- |
| `-a size=48` | 每一塊剛好 48 位元組的堆積記憶體 |
| `-a size=1k..64k` | 某個大小範圍（包含系統配置器不會上標籤的大小） |
| `-a caller=make_node` | 配置時最內層 4 個呼叫者裡有 `make_node` 的記憶體（用 `depth=N` 調整） |
| `-a caller=make_node,off=16,len=8` | 上述每一塊的第 16–23 位元組 |
| `-a size=64,every=100,limit=50` | 每 100 塊取 1 塊，最多 50 塊 |
| `-s g_table:64`、`-s name=cache,image=libfoo.dylib` | 依符號名稱監看全域變數 |

即時記錄（預設印到 stderr）會在每次存取發生時印出來：

```
$ build/tagwatch run --depth 4 -s g_counter -- build/mte/target_list
tagwatch: watch #1 armed: 8 bytes at 0x100a70020 "g_counter"
tagwatch: #1 READ  8 bytes at 0x100a70020  watch #1 "g_counter" +0  thread 10410595
    bump+0x8 (target_list)
    main+0x88 (target_list)
    start+0x1a20 (dyld)
tagwatch: #2 WRITE 8 bytes at 0x100a70020  watch #1 "g_counter" +0  thread 10410595
    bump+0x10 (target_list)
    main+0x88 (target_list)
    start+0x1a20 (dyld)
```

追蹤檔（`-t file.jsonl`）每行一個 JSON 物件，種類有 `start`、`watch`、`access`、`free`、`unwatch`、`violation`、
`note`、`stats`。`tagwatch report [--heatmap] file.jsonl` 可以從存下來的追蹤檔再印一次總結。熱度圖顯示物件的哪些
部分被碰到，同一種物件會加總在一起：

```
Heat map of 4 objects "make_node" (40 bytes each, 8 bytes per row)
    offset       reads    writes
    +0               7         8  ########################################
    +8               5         7  ################################
    +16              0        12  ################################
    ...          (2 untouched rows)
```

`tagwatch run` 的結束碼就是被執行程式自己的結束碼（被訊號殺掉時是 128 + 訊號編號）。

## 函式庫用法

連結 `libtagwatch.dylib`，再用兩個 MTE entitlement 簽署你的程式（這樣直接執行時就有 MTE），或者用
`tagwatch run` 執行（不需要 entitlement）。

```c
#include "tagwatch.h"

int main(void) {
    if (tagwatch_init() != 0) { /* 這台機器沒有 MTE：下面的呼叫都不會做任何事 */ }

    struct config *cfg = load_config();                   // 一般 malloc 出來的物件
    tagwatch_watch(&cfg->timeout, sizeof cfg->timeout, "timeout");   // 誰讀寫這個欄位？

    char *big = tagwatch_alloc_watched(1 << 20, "frame"); // 任意大小，來自 tagwatch 自己的 MTE 記憶體區

    static long table[64];
    tagwatch_adopt(table, sizeof table);                  // 先讓全域變數可以上標籤，然後：
    tagwatch_watch_mode(&table[3], 8, "table[3]", TAGWATCH_WRITE);
    ...
}
```

```sh
cc -Iinclude app.c -Lbuild -ltagwatch -Wl,-rpath,@executable_path/build -o app
codesign -s - --entitlements entitlements/mte.entitlements -f app
./app
```

`tagwatch_init()` 要在 `main` 一開始就呼叫：除非行程是 `tagwatch run` 啟動的，否則它會 **fork**，原本的行程留下來
當追蹤者（見下一節）。完整 API 說明在 [`include/tagwatch.h`](include/tagwatch.h)。

## 運作原理

```
 程式的執行緒                             例外處理執行緒（在同一個行程裡）              tagwatch run（父行程）
 ────────────                             ──────────────────────────────              ────────────────────
 str x1, [x0]      ; x0 指向被監看的記憶體
   └─ 標籤檢查錯誤 ───Mach 例外──────────▶ 在監看表裡查這個位址
      （執行緒被凍住）                      解碼指令：位址、寬度、讀或寫
                                           沿著 frame pointer 走堆疊、查符號、寫記錄
                                           找到（或產生）這個 pc 專用的小段程式碼：
                                             msr TCO, #1      ; 只對這條執行緒關掉檢查
                                             str x1, [x0]     ; 同一道指令
                                             msr TCO, #0
                                             b   pc+4
   ◀──────回覆：從那段程式碼繼續───────────┘
 （執行那一小段，再回到 str 的下一道指令）                                             等待；轉送訊號
```

1. **設置。** 對監看範圍裡每個 16 位元組的粒度，先讀出目前的標籤（`LDG`）記下來，再寫入一個不同、而且不是 0 的
   標籤（`STG`）。從這一刻起，程式手上的每個指標都對不上。
2. **出錯。** 存取會引發同步的標籤檢查錯誤。行程的 `EXC_BAD_ACCESS` 例外埠由行程內的一條執行緒負責；訊息裡帶著
   出錯執行緒的暫存器，回覆時可以改掉它們。
3. **記錄。** 處理程式解碼那道指令得到精確的位址、寬度和方向，沿著 frame pointer 走出呼叫堆疊（用 compact unwind
   資料把 `memmove` 這類葉函式處理正確），從記憶體裡的 Mach-O 映像查出符號，寫出記錄。
4. **放行，但不解除監看。** 處理程式讓執行緒改去執行一小段動態產生的程式碼（每個出錯的指令位址一段）：把同一道
   指令夾在 `MSR TCO, #1` 和 `MSR TCO, #0` 之間執行（TCO 只會關掉「正在執行的這條執行緒」的標籤檢查），然後跳回去。
   記憶體上的標籤從頭到尾沒被動過。
5. **監督者。** macOS 會在標籤檢查錯誤時殺掉行程，除非它被追蹤，所以目標會呼叫 `ptrace(PT_TRACE_ME)`。它的父行程
   （`tagwatch run`，或函式庫模式下 fork 出來的那一份）只負責等待和轉送訊號。

為什麼長這樣、試過哪些做法又放棄，寫在 [docs/DESIGN.md](docs/DESIGN.md)。

### 多執行緒時保證什麼

因為放行某條執行緒時，被監看的粒度仍然帶著監看用的標籤，所以同一時間其他執行緒碰它一樣會出錯。任何執行緒的每一次
「會做標籤檢查的存取」都恰好被攔一次、恰好生效一次。`t_threads` 用精確的數字驗證這件事（8 條執行緒、36 000 次存取，
全部有回報、數值全部正確），`t_signal` 則驗證計時器訊號打在正在處理攔截的執行緒上時也成立。

不在保證範圍內的（來自 MTE 或這個機制本身的性質）：

- 用 `[sp, #imm]` 定址的存取（MTE 從不檢查，所以堆疊上的變數只看得到「透過指標」的存取）；
- 核心在 tagwatch 沒有包裝的系統呼叫裡所做的存取（下一節）；
- 呼叫了 `tagwatch_pause()` 的執行緒；
- 事件編號是「被處理的順序」；兩條執行緒搶同一個粒度時，實際生效的順序可能相反。

## 困難的情況

每一列都有在 MTE 硬體上執行的測試（`make test`）。

| 情況 | 結果 | 測試 |
| --- | --- | --- |
| 多條執行緒碰同一個粒度 | 全部攔到，數量精確。 | `t_threads`、`t_far` |
| 別的執行緒在存取時設置／解除監看 | 已經在路上的錯誤會重試，不會被當成真的錯誤。 | `t_threads` |
| 對被監看的緩衝區做 `read`/`write`/`pread`/`pwrite`/`recv`/`send`/`fread`/`fwrite` | 核心碰到被設置的粒度會直接致命（下一列），所以改用一塊暫時的緩衝區做系統呼叫，再關掉標籤檢查複製資料，並回報成「核心做的存取」，附上呼叫者的堆疊。 | `t_syscall` |
| 其他系統呼叫碰到被監看的緩衝區（`readv`、`getcwd`、`ioctl`…） | **沒有處理：** 核心發生致命的標籤錯誤，行程被殺掉（結束碼 137）。 | `cli.sh` |
| 大塊配置（系統配置器只幫大約 4 KB 以下的區塊上標籤） | 符合條件的配置改由 tagwatch 自己的 MTE 記憶體區提供，大小不限。 | `t_alloc`（測到 70 MB） |
| 全域變數 | 把所在的分頁就地換成有 MTE 的副本（稱為「收編」，過程中暫停其他執行緒）。`-s` 會自動做。 | `t_adopt`、`cli.sh` |
| 堆疊記憶體 | 可以收編並監看**別條**執行緒的堆疊；只看得到透過指標的存取。執行緒不能收編自己的堆疊。 | `t_adopt` |
| 程式碼與唯讀的檔案對應分頁 | 不能收編；`tagwatch_watch` 回傳 `TAGWATCH_ENOTTAGGED`。 | `t_adopt`、`t_basic` |
| `free` 被監看的物件 | 監看會留在隔離區（預設 1 MB）繼續生效，之後的存取會回報成**釋放後使用**；離開隔離區才解除並重用記憶體。重複釋放會被回報。 | `t_alloc` |
| `realloc` | 關掉標籤檢查搬移內容；新區塊符合規格就繼續監看。 | `t_alloc` |
| `fork` | 監看不會跟到子行程：子行程開始執行前，所有粒度都會換回原本的標籤，之後不受監看。父行程不受影響。 | `t_fork`、`cli.sh` |
| `exec` | 新程式不受監看，也不會被插入函式庫；結束碼照樣傳回來。 | `cli.sh` |
| 訊號 | 由監督者轉送。訊號處理函式會被包一層，確保它打斷那一小段程式碼時仍然開著標籤檢查。`wait`/`read`/`write` 系列的阻塞呼叫被追蹤造成的暫停打斷時會自動重試。 | `t_signal`、`cli.sh` |
| 系統函式庫裡的程式碼（`memcpy`、`strlen`、zlib…） | 和其他程式碼一樣被追蹤；堆疊能正確穿過葉函式。 | `t_insn` |
| 離任何空閒位址空間超過 128 MB 的程式碼（dyld 共用快取深處） | 那一小段程式碼跳不回去，改用中斷點結尾：每次存取兩次例外而不是一次。 | `t_far`、`t_insn`（zlib） |
| `LDXR`/`STXR` 迴圈 | 不能重新執行（出錯會清掉獨佔監視器），所以把這一對模擬成 compare-and-swap。 | `t_insn` |
| 程式裡真正的 MTE 違規（目標現在是開著 MTE 在跑） | 附上堆疊回報為「不是監看點」，然後程式照原本會發生的方式結束。 | `cli.sh` |

## 量測

Apple M5（10 核心、16 GB）、macOS 27.0、Apple clang 17，2026 年 10 月 1 日。量測時機器同時有別的工作在跑（負載
平均 3–7），數字請當作 ±15%。每個數字是 5 次執行的中位數。用 `make bench` 重現；方法和原始輸出在
[docs/BENCHMARKS.md](docs/BENCHMARKS.md)。

**每次被攔下的存取**

| 機制 | 每次存取（微秒） |
| --- | --- |
| tagwatch，事件只交給 callback，不寫任何東西 | 4.7 |
| tagwatch，寫出 JSON 記錄（含 16 層已查符號的堆疊） | 6.6 |
| tagwatch，JSON 記錄加即時記錄 | 7.6 |
| tagwatch，慢速返回路徑（程式碼離空閒位址太遠，兩次例外） | 8.9 |
| 換回標籤＋單步執行＋再換標籤（最直覺的設計；已放棄，而且有競爭問題） | 15.5 |
| `mprotect` 分頁監看（出錯、單步、兩次 `mprotect`） | 16.3 |
| 沒被攔的存取（對照用） | 0.0001 |

**實際工作負載的額外成本。** `bench/kv.c`：10 萬個堆積節點（各 48 位元組）的雜湊表，對隨機鍵做一百萬次查詢與更新；
計時的是操作階段。

| 設定 | 時間（毫秒） | 攔截次數 | 變慢倍數 |
| --- | --- | --- | --- |
| 原生，沒開 MTE | 10.0 | – | 1.0× |
| 開 MTE，沒載入 tagwatch（`--no-runtime`） | 10.0 | – | 1.0× |
| 載入 tagwatch，但沒有符合的物件 | 9.9 | 0 | 1.0× |
| 監看 1 個節點 | 10.7 | 23 | 1.1× |
| 監看 10 個節點（萬分之一） | 14.2 | 428 | 1.4× |
| 100 個節點（千分之一） | 41.3 | 4 068 | 4.1× |
| 1 000 個節點（百分之一） | 309 | 40 116 | 31× |
| 10 000 個節點（十分之一） | 2 954 | 405 522 | 295× |
| 全部 100 000 個節點 | 28 156 | 4 049 194 | 2 800× |

成本只和被攔下的存取次數成正比（這裡每次約 7 微秒）：大程式裡監看幾個物件幾乎量不出影響，把熱迴圈裡的每個物件都
監看起來則會慢上三個數量級。（操作階段沒有配置記憶體，所以這張表沒有量到配置攔截器的成本；沒有配置規格時，它對
每次 `malloc` 多一個分支判斷。）

**同一個任務改用分頁保護。** `bench/pagewatch.c` 跑同樣的工作負載，用保護分頁的方式監看同樣的節點。兩個工具回報的
「真正碰到被監看節點的次數」完全一樣，正好互相驗證：

| 監看對象 | 工具 | 時間（毫秒） | 攔截次數 | 真正碰到被監看節點的次數 | 誤攔比例 |
| --- | --- | --- | --- | --- | --- |
| 1 個節點 | tagwatch | 9.8 | 23 | 20（建表時另有 3 次） | 0 |
| 1 個節點 | mprotect | 32.0 | 1 300 | 20 | 98.5% |
| 100 個節點 | tagwatch | 43.0 | 4 068 | 3 768（建表時另有 300 次） | 0 |
| 100 個節點 | mprotect | 20 383 | 1 267 454 | 3 768 | 99.7% |

一個 16 KB 的分頁放得下大約 340 個這種節點，所以分頁監看每攔到一次有用的，就要多攔大約 340 次沒用的。100 個被監看的
節點分散在 100 個分頁時，它在這個工作負載上比 tagwatch 慢 470 倍。

**硬體監看點。** `sysctl hw.optional.watchpoint` 在 M5 上回報 **4** 個除錯暫存器，這就是 LLDB 監看點的上限；
上面的表格則同時監看了 10 萬個物件。LLDB 本身我沒辦法計時：開發用的機器沒開開發者模式，我也沒有管理員權限，LLDB
無法啟動行程。替代做法是 `bench/hwwatch.c` 在行程內直接設定同樣的除錯暫存器；有送達的命中每次花 17–33 微秒，但在
這種用法下只有一小部分命中會送達（記錄的那次是 5 000 次裡 36 次），所以它不能當比較基準，除了暫存器數量之外我不
從中下任何結論。

## 限制

- **平台。** M5 或更新，只測過 macOS 27.0。依賴私有的 spawn SPI、沒有文件的 `VM_FLAGS_MTE` 對應，以及核心對
  「被追蹤的行程」的處理方式；這些都可能改變。
- **被追蹤有副作用。** 目標每收到一個訊號都會停住，等監督者轉送，所以訊號變慢；阻塞的系統呼叫也可能在沒有任何
  處理函式執行的情況下回傳 `EINTR`。tagwatch 會替 `wait`、`read`、`write` 系列重試；其他呼叫（`select`、`poll`、
  `nanosleep`、`accept`…）沒有處理，沒有自己處理 `EINTR` 的程式可能出問題。
- **沒包裝的系統呼叫碰到被監看的記憶體會殺掉行程**（見上表）。
- **不能 attach；不能用在 hardened runtime 或受 SIP 保護的程式；不支援 arm64e。**
- **`fork` 和 `exec` 會結束監看**（對子行程／新程式而言）。
- **堆疊變數**只看得到透過指標的存取；**程式碼和唯讀的檔案對應資料**不能監看。
- **攔截的粒度是 16 位元組。** 同一粒度裡的鄰居每次存取都要付一次攔截成本（不會出現在報告裡）。
- **被監看的配置住在 tagwatch 自己的記憶體區**，不在系統堆積裡：位址、鄰居、重用方式都和沒監看時不同，可能讓
  跟記憶體配置位置有關的 bug 消失或換地方。
- **處理程式在行程裡面。** 亂寫記憶體的程式也可能寫壞 tagwatch 的狀態。自己安裝 `EXC_BAD_ACCESS` 例外埠的程式
  （有些當機回報工具會）會把處理程式換掉。
- **LL/SC 模擬**用 compare-and-swap，看不到 `LDXR` 和 `STXR` 之間 A→B→A 的變化。
- **會自我修改或 JIT 產生的程式碼**：如果在別的執行緒正在執行那一小段程式碼時改掉指令，沒有處理；下次在同一位址
  出錯時才會重寫。
- **呼叫堆疊**依賴 frame pointer（Apple 平台的標準做法），顯示的是「符號名稱＋位移」，不是檔名和行號。總結會把
  C++ 名稱還原。尾端呼叫（tail call）會讓某些層消失，和任何除錯器一樣。
- **成本**是每次被攔的存取 5–9 微秒。監看每秒被碰幾百萬次的記憶體，程式會慢上幾千倍。
- **函式庫模式會在 `tagwatch_init()` 裡 fork**，而且在那之前安裝的訊號處理函式不會被包裝。

## 測試

```sh
make unit       # 不需要 MTE 的邏輯；CI 在 macos-latest 上跑的就是這個
make sanitize   # 同樣的測試加上 UBSan（CI 再加上 AddressSanitizer）
make lint       # -Werror 編譯加上 clang 靜態分析
make mte-test   # 需要 MTE 的全部測試；在其他硬體上會印出 SKIP 和原因
```

單元測試涵蓋：指令解碼器（對照真正的組譯器產生的編碼，再加兩百萬個隨機字）、監看表（對照參考模型，並注入配置
失敗）、規格語法與 JSON 讀取器（來回轉換的性質）、符號查詢（對照 `dladdr`）、報告。隨機測試使用固定種子，失敗時
會印出種子。

GitHub 提供的執行機是沒有 MTE 的 M1/M2，所以 CI 只會把 MTE 測試編譯起來並回報「略過」。
**MTE 測試是在本機的 Apple M5（macOS 27.0）上跑的。** 在那台機器上 `make test` 的輸出：

```
ok   fmt            20024 checks
ok   insn           2379659 checks
ok   wtab           686182 checks
ok   spec           60069 checks
     (memmove unwind mode 1, leaf 3)
ok   symtab         233 checks
ok   json           160033 checks
ok   report         55 checks
     (sp-relative store to a watched stack slot: not reported, as MTE never checks [sp, #imm] accesses)
ok   adopt      33 checks
     (58 watches armed in total, 5 still live in quarantine)
ok   alloc      75 checks
ok   basic      62 checks
ok   far        8 checks
ok   fork       16 checks
     (libz crc32 over the watched window: 2 traps; 2 traps so far took the slow return path)
ok   insn       245 checks
     (544 timer signals delivered during 20000 traps; all 20544 accesses reported)
ok   signal     25 checks
ok   syscall    103 checks
     (9794 accesses caught during 3000 arm/disarm cycles with 4 threads running)
ok   threads    3041 checks
ok   cli        53 checks
MTE tests passed
```

## 相關研究

這個技術本身不是新的。把 MTE 的標籤不符當成便宜又精細的「存取陷阱」，在 Linux 和 Android 上已經有人做過；這個
專案做的是讓它在 macOS 上成為一個能用的工具。macOS 上的每個環節（不靠 entitlement 開 MTE、在標籤錯誤後活下來、
替配置器不上標籤的記憶體上標籤）都不一樣，而且大多沒有文件。就我所知，截至 2026 年 9 月，macOS 上還沒有這樣的
工具。

- **Noh 等人，〈ARM MTE Performance in Practice〉**（[arXiv:2601.11786](https://arxiv.org/abs/2601.11786)）裡有
  *MTE-tracer*，一個在 Pixel 8 上的使用者空間記憶體追蹤工具。依論文的描述，它替目標資料上標籤，在訊號處理函式裡
  接住錯誤，執行一段動態產生的「記錄、單步、繼續」程式碼：先拿掉標籤、重新執行指令、再把標籤放回去。tagwatch 和它
  一樣是「每個出錯位置一段產生的程式碼」；不同的地方是 tagwatch 不動標籤，而是用 `PSTATE.TCO` 暫時關掉檢查（所以
  多執行緒下是安全的），定位是監看點工具而不是效能量測的對象，平台也不同。他們靠核心模組加速的版本，這裡沒有對應物。
- **HMTRace**（[arXiv:2404.19139](https://arxiv.org/abs/2404.19139)）在 Armv8.5 Linux 上用 MTE 偵測 C 程式的資料
  競爭：同一個硬體機制，回答的是另一個問題（誰和誰競爭）。
- **NanoTag**（[github.com/ice-rlab/nanotag](https://github.com/ice-rlab/nanotag)，IEEE S&P 2026）在 Android 上用
  「絆線」配置加上錯誤處理函式裡的軟體檢查，讓 16 位元組的 MTE 能偵測到位元組等級的溢位。tagwatch 的「依位址過濾」
  是這個想法簡單得多的親戚，本身不偵測任何東西。
- **LLDB 的 `process launch --memory-tagging`**（[llvm-project PR 162944](https://github.com/llvm/llvm-project/pull/162944)）
  是 `tagwatch run` 用的那個 spawn SPI 公開可見的出處。LLDB 用它讓程式開著 MTE 檢查執行；它的監看點仍然是那 4 個
  硬體監看點。
- **Apple-MTE-Research**（[github.com/kaffeindecaf/Apple-MTE-Research](https://github.com/kaffeindecaf/Apple-MTE-Research)）
  和 **8kSec 的〈MIE deep dive〉**（[8ksec.io/mie-deep-dive-enabling-apps](https://8ksec.io/mie-deep-dive-enabling-apps/)）
  記錄了 Apple 的 Memory Integrity Enforcement 怎麼啟用、標籤錯誤長什麼樣子。兩者都不是追蹤工具。
- 分頁保護式監看點和硬體監看點是傳統的替代做法，上面都量過了。

## 用途範圍

tagwatch 是拿來除錯「你自己編譯、自己執行的程式」的。它沒有辦法附加到執行中的行程，不能用在 hardened 或系統
程式上，也不會削弱 MTE 的保護：被追蹤的程式檢查只會**更多**，真正的違規會被回報，而且仍然是致命的。

## 目錄結構

```
include/tagwatch.h   公開的 C API
src/                 執行期函式庫（libtagwatch.dylib）；逐檔說明見 docs/DESIGN.md
cli/                 tagwatch run / report / check
tests/unit/          不需要 MTE 的測試（CI）
tests/mte/           需要 MTE 的測試：函式庫模式測試、CLI 的目標程式與 cli.sh
examples/            ledger.c，上面示範用的例子
bench/               量測程式與比較用的基準
experiments/         設計決策背後的小實驗，附記錄下來的結果
```

## 授權

MIT，見 [LICENSE](LICENSE)。
