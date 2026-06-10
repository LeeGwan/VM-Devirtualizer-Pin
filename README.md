# VMAnalyzer — a VM-obfuscation analysis tool built with Pin

> English | [한국어](./README.ko.md)

A dynamic analysis tool I built with Intel Pin to help analyze VM-based obfuscation
(code virtualization). It hooks the VM dispatcher at runtime and produces a
region-labeled log of what each handler reads and writes.

## Why virtualized code is so hard to reverse

Code virtualization doesn't simply hide the original code — it virtualizes the code so
that the real CPU no longer executes it directly. Instead it builds a *virtual CPU* and
has that process the code. Inside, before control passes from the real CPU to the
virtual one, a controller sets up register values and does various preparation; then a
**fetch instruction** reads an opcode, the encrypted form is decrypted, and the matching
handler — one of the `vm_handler` entries — is invoked.

But getting that far is buried under heaps of obfuscated code, useless garbage code, and
garbage handlers. So once code virtualization is in place, reversing becomes painfully
slow. To cut that down, I used the Intel Pin API to watch which handlers actually run
and what they read and write — filtering out the unnecessary code piece by piece so that
only the handlers and code that really do the work get extracted for analysis.

## What I ran into while building it

The first version just dumped every memory read and write inside the VM region. It
worked, but the log was flooded with **garbage values** — the dispatcher's own decode
routine constantly touches memory, and all of that came through as noise.

The fix came from digging deeper into the Pin API. `INS_IsStackRead` /
`INS_IsStackWrite` to classify stack accesses accurately, `IPOINT_TAKEN_BRANCH` to catch
the exact moment of the jump into a handler, and a check that detects the noise window
from the signature values the decode routine writes to the stack (`0x4b82`, `0x25c5`) and
skips log output for that window until the next handler is entered — adding these
primitives one by one let me refine the trace until it produced exactly as clean a result
as I wanted.

## How it works

- Finds the `.v-lizer` section to locate the VM region.
- Turns tracking of the virtualized execution window on/off around `PUSHAD`/`POPAD`.
- Records handler entry and the virtual opcode at the dispatcher jump (`jmp [edi+eax*4]`).
- Catches memory reads/writes and `LEA`, printing the address and value along with a
  region label (`vm_context`, `[STACK]`, `[MEM]`, etc.).
- On exit, summarizes per-handler call/read/write counts.

## Example output

```
[0x00000047] op(DECODING)=0x0000001a handler=0x0041f6a6
      WRITE [STACK]0x0019fde0 <- 0x00000051 (->STACK)
      WRITE [init_flag]0x0041e630 <- 0x00006ae5
      READ  [STACK]0x0019fde0 val:0x00000051 (->STACK)
      READ  [init_flag]0x0041e630 val:0x00006ae5
      WRITE [init_flag]0x0041e630 <- 0x00000000
      READ  [STACK]0x0019fde4 val:0x0019fee4 (->STACK)

================= HANDLER SUMMARY =================
handler        callscount       readscount     writescount    opcode(Decoding)
0x0041ec7e   0x00000001    0x00000006    0x00000006    0x00000076
0x0041ee2a   0x00000001    0x00000006    0x00000006    0x0000007a
0x0041f566   0x00000012    0x0000007e    0x000000b4    0x0000002d
0x0041f6a6   0x00000001    0x00000003    0x00000003    0x0000001a
0x0041fae3   0x00000002    0x0000000e    0x00000010    0x0000009b
0x0041fb23   0x00000009    0x0000002d    0x0000002d    0x00000025
0x0041fb68   0x00000004    0x00000020    0x00000028    0x0000005e
0x0041fdb4   0x00000002    0x00000010    0x0000000e    0x0000001d
0x004202ce   0x00000001    0x00000008    0x00000008    0x00000058
0x004202e0   0x0000000a    0x00000032    0x00000032    0x00000032
0x004207e6   0x00000001    0x0000000c    0x0000000b    0x00000033
0x004208b2   0x00000001    0x00000008    0x00000007    0x00000094
0x00421482   0x00000014    0x00000078    0x00000064    0x00000089
0x004218bf   0x00000001    0x00000005    0x00000004    0x00000075
==================================================
```

The trace at the top shows exactly how one handler (`op=0x1a`) reads and writes the stack
and `init_flag`, while the summary below gives the per-handler call/read/write counts and
the decoded opcode at a glance (all values are hexadecimal). It's a good starting point
for recovering the meaning of each handler one at a time.

> Note: the reads/writes in the summary are raw counts that include decoding noise, so
> they can be larger than the number of lines actually printed in the trace above.

---
Download: https://www.intel.com/content/www/us/en/developer/articles/tool/pin-a-binary-instrumentation-tool-downloads.html
Version: Pin 3.31 (EOL)
*Runs on a 32-bit x86 target with Intel Pin (JIT mode). Use it only on targets you're
authorized to analyze, and for learning/research purposes only.*
