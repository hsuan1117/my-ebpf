# tutorial-simple-example

- This repository contains 2 example eBPF programs: `minimal` and `bootstrap`.
- 如需在codespace/devcontainer內編譯`bootstrap`，則需在編譯參數LD的地方加上`/usr/lib/libargp.a`
- 如有`#include <asm/types.h>`找不到檔案的[情況](https://stackoverflow.com/a/77465534/6607512)，可以執行下列指令:
```bash
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

## 0. Setup Environment
### a. VirtualBox
- https://drive.google.com/drive/folders/1LbSv4U3Q2M-KiFXZMa5NezVZr4TO6bP2?usp=sharing
### b. Ubuntu
- `sudo apt install -y bpftool libbpf-dev build-essential clang`
### c. Codespace/devcontainer (不推，有的程式會跑不了)
- https://docs.github.com/en/codespaces/getting-started/quickstart
- https://code.visualstudio.com/docs/devcontainers/tutorial

## 1. 檔案概述
- `some_program.bpf.c` :  
  This is the eBPF program we're going to load into the Kernel.

- `some_program.c` :  
  This file is our frontend in the userspace, and it is responsible for loading the eBPF program into Kernel.

## 2. 編譯流桯
<img width="1247" alt="image" src="https://github.com/user-attachments/assets/18ab4519-c925-4d4c-a5e7-3209801e1c4f">

