#!/usr/bin/env python3

import openai
import os

# Either set your API key here or export OPENAI_API_KEY in your environment:
# export OPENAI_API_KEY='your-key-value'
openai.api_key = os.environ.get("OPENAI_API_KEY", "YOUR_OPENAI_API_KEY")

MODEL_NAME = "gpt-4o"

def semantic_probing(code_snippet_kernel1: str, code_snippet_kernel2: str) -> str:
    """
    Performs a semantic comparison (semantic probing) between two kernels' 
    eBPF kprobe or tracepoint code snippets using OpenAI's GPT model.
    """
    
    # Create the conversation (system + user messages).
    # The system role sets context or instructions for the LLM.
    # We then give the user prompt with the two snippets to compare.
    messages = [
        {
            "role": "system",
            "content": (
                "You are a code analysis assistant with expertise in eBPF, "
                "Linux kernel internals, and hooking/tracing with kprobes and tracepoints. "
                "You will compare two eBPF code snippets to determine if they are semantically similar."
            )
        },
        {
            "role": "user",
            "content": (
                "Below are two eBPF kprobe (or tracepoint) hookpoint code snippets from "
                "two different Linux kernels. Perform a semantic analysis to see if they are:\n"
                "1) Functionally identical.\n"
                "2) Slightly different but similar in overall behavior.\n"
                "3) Significantly different and may cause different behavior.\n\n"
                "Please identify relevant function calls, data structures, or offsets that changed. "
                "If they are different, explain the difference in functionality, including what might "
                "break if the code was transplanted to the other kernel."
            )
        },
        {
            "role": "user",
            "content": f"Kernel 1 eBPF snippet:\n```\n{code_snippet_kernel1}\n```"
        },
        {
            "role": "user",
            "content": f"Kernel 2 eBPF snippet:\n```\n{code_snippet_kernel2}\n```"
        }
    ]
    
    response = openai.ChatCompletion.create(
        model=MODEL_NAME,
        messages=messages,
        temperature=0.3,
        max_tokens=1000
    )
    
    # The assistant's answer should contain a semantic comparison
    # We extract the content from the response.
    return response["choices"][0]["message"]["content"]


if __name__ == "__main__":
    # Example usage:
    # Replace these with actual eBPF kprobe/tracepoint code samples from two different kernels.
    kernel1_code = r"""
    // eBPF code snippet from Kernel 1
    SEC("kprobe/sys_open")
    int bpf_prog1(struct pt_regs *ctx) {
        char filename[256];
        bpf_probe_read_user_str(&filename, sizeof(filename),
                                (void *)PT_REGS_PARM1(ctx));
        bpf_printk("Kernel1: Opening file: %s\n", filename);
        return 0;
    }
    """

    kernel2_code = r"""
    // eBPF code snippet from Kernel 2
    SEC("kprobe/do_sys_open")
    int bpf_prog2(struct pt_regs *ctx) {
        char fname[256];
        bpf_probe_read_user_str(&fname, sizeof(fname),
                                (void *)PT_REGS_PARM2(ctx));
        bpf_printk("Kernel2: Attempting open: %s\n", fname);
        return 0;
    }
    """

    analysis_result = semantic_probing(kernel1_code, kernel2_code)
    print("=== Semantic Probing Analysis Result ===")
    print(analysis_result)