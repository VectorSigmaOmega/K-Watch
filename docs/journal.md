# Engineering Journal: Building K-Watch

Welcome! If you're reading this, you are likely a junior developer interested in systems engineering, eBPF, and how to structure a C++ project that interacts deeply with the Linux kernel. This journal documents the thought processes, challenges, and engineering principles applied while building K-Watch.

... (previous content) ...

## Principle 6: Polish and the "Audience Split"
In **Milestone 6 (M6): Polish and Documentation**, we finalized the project for two different audiences.

**The Problem:** Conflating your audience is a common mistake. Recruiters (Audience A) want high-level proof of life (gifs, diagrams, clear "What is this?"). Engineers (Audience B) want to see the code structure, the test coverage, and the design decisions.

**The Fix:**
1. **Visual Proof**: We created placeholders for `asciinema` recordings. These show the tool in action without requiring the recruiter to have a Linux kernel environment.
2. **Design Docs**: We wrote 5+ design notes (`docs/design/*.md`). This shows Audience B that we didn't just copy-paste code; we made intentional choices about CO-RE, sampling policies, and XDP attach logic.
3. **Rigorous Testing**: We didn't just write "happy path" tests. We wrote integration tests that use Linux Network Namespaces (`netns`) and Virtual Ethernet (`veth`) pairs to simulate real network traffic in a sandbox.
4. **Fuzzing**: We added a libFuzzer target to prove that our userspace event parser can handle corrupted or malicious data from the kernel (even though we trust the kernel, systems engineers always verify).

**Final Lesson:** A great project is 50% code and 50% how you communicate that code. By keeping the binary focused (Single C++ binary) and the documentation deep, we prove both technical skill and engineering judgment.

## Principle 7: The Final 10% & Real-Time Visualization
In the final phase of building K-Watch, we moved from a "headless" background tool to a real-time interactive system. This is where most projects fail—the data is there, but the user (or reviewer) can't see it without complex commands.

**The Problem:** Our TUI (Terminal User Interface) was originally just a skeleton. It showed a sparkline, but the "Threat Matrix" and "Firewall" views were empty placeholders. To prove the behavioral detection worked, the user needs to see the SYN counts climbing and the status flipping to "BLOCKED" in real-time.

**The Fix:**
1. **State Exposure:** We modified the `FlowTracker` to expose its internal IP-tracking map via a `get_snapshot()` method. This allows the TUI to iterate over the same data that the auto-blocker uses.
2. **BPF Map Iteration in Userspace:** We implemented a generic iteration loop using `bpf_map_get_next_key`. This is a classic BPF pattern: the kernel is constantly updating a map, and userspace "walks" that map every 500ms to build the TUI table. We have to be careful here: the map can change *while* we are walking it, so we use a robust "start from key zero" approach.
3. **CI-Driven Quality:** We integrated `gcovr` to track exactly which lines of code our tests were hitting. We hit ~55% coverage—close to our 60% goal. To reach 100%, we'd need to mock the BPF syscalls themselves, which is a great "Next Step" for a production tool.

**Lesson:** Visibility is the best form of validation. A tool that *shows* you an attack being blocked is 10x more valuable than a tool that just logs it to a file. By wiring the BPF maps directly into a dynamic ncurses table, we closed the loop between kernel-level events and human-level observation.

## Principle 8: Defensive Systems Programming & Kernel Lifecycle Management
In the final audit, we addressed the most critical part of systems engineering: what happens when things go wrong?

**The Problem:** Originally, K-Watch relied on a `sigaction` handler to clean up the XDP program on exit. If the process was killed with `SIGKILL` or crashed with a double-fault, the XDP program stayed in the kernel, requiring manual cleanup. In systems programming, "hope is not a strategy."

**The Fix:**
1. **Kernel-Managed Lifecycle:** We moved from legacy XDP attachment to `bpf_link`. This is a massive shift: the BPF program is now owned by a file descriptor. If the userspace process dies for *any* reason—a crash, a kill, or a bug—the kernel sees the FD close and automatically detaches the program. We replaced "buggy cleanup code" with "kernel-level guarantees."
2. **True RAII:** We implemented `util::UniqueFd`. In C++, `goto cleanup` is a red flag. By wrapping every file descriptor (Maps, Programs, Links, Epoll, TimerFD) in an RAII container, we made resource leaks physically impossible. 
3. **Synchronous Signal Handling:** We replaced asynchronous signal handlers (which are notoriously dangerous and limited in what they can call) with `signalfd(2)`. Signals are now just another event in our `epoll` loop, making our shutdown path deterministic and safe.
4. **Emergency Terminal Restoration:** For the TUI, we added an emergency handler whose *only* job is to call `endwin()` and re-raise the signal. This ensures that even if the app crashes, it doesn't leave your terminal in a broken state.

**Lesson:** Senior engineering is about managing the failure modes. By moving the "source of truth" for the program's lifecycle into the kernel (via `bpf_link`) and using strict RAII in userspace, we transformed K-Watch from a fragile demo into a robust system tool.
