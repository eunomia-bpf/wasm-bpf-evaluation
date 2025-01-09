#!/usr/bin/env python3

import os
from dotenv import load_dotenv

# 1) For LLM and embeddings
import openai
from langchain.chat_models import ChatOpenAI
from langchain.embeddings.openai import OpenAIEmbeddings

# 2) For vector storage & retrieval
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.vectorstores import FAISS
from langchain.chains import ConversationalRetrievalChain

# 3) For LLM "Memory" in QA
from langchain.memory import ConversationBufferMemory

# 4) For prompts, if we want to customize the system message
from langchain.prompts import PromptTemplate

# Load environment variables (including OPENAI_API_KEY) from .env, if desired
load_dotenv()

def load_ebpf_docs(doc_path: str) -> str:
    """
    Simple helper function to read the ebpf documentation
    from a local .txt file. 
    """
    with open(doc_path, 'r', encoding='utf-8') as f:
        return f.read()

def build_vectorstore(text: str):
    """
    Build a FAISS vectorstore from the ebpf docs text.
    Splits the text into chunks, then embeds and stores.
    """
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=1000,      # adjust chunk size as needed
        chunk_overlap=100     # adjust overlap as needed
    )
    docs = text_splitter.create_documents([text])

    # Create embeddings using OpenAI Embeddings
    embeddings = OpenAIEmbeddings()

    # Build a FAISS Vectorstore
    vectorstore = FAISS.from_documents(docs, embeddings)
    return vectorstore

def create_agent(vectorstore):
    """
    Create a conversational retrieval chain (the 'Generative Agent').
    The chain includes memory for conversation history and retrieval for context.
    """
    # We can define a custom system prompt if needed. For example:
    system_template = """
    You are ebpfDocBot, an AI assistant specialized in ebpf (Kernel Runtime Integrity with eBPF).
    Use the retrieved ebpf documentation to answer the user's question. If the answer doesn't appear 
    in the documentation, say you don't know. Cite relevant details from the text where possible.

    The user may ask about:
     - ebpf's licensing
     - Basic usage, building, and configuration
     - System requirements
     - Potential limitations
     - Differences between eBPF and Go code licensing (GPL vs Apache 2.0)
     - BTF debug information, etc.

    Always ensure answers are consistent with the ebpf documentation. 
    """

    prompt = PromptTemplate(
        input_variables=["context", "question"],
        template="""
{context}

Question: {question}

Answer as helpfully as possible, citing relevant ebpf docs information when you can.
        """,
    )

    # ChatOpenAI is the recommended LLM wrapper around gpt-3.5-turbo or gpt-4
    llm = ChatOpenAI(
        model_name="gpt-3.5-turbo",  # or "gpt-4"
        temperature=0.2
    )

    # Memory to keep track of conversation
    memory = ConversationBufferMemory(
        memory_key="chat_history",
        return_messages=True
    )

    # Build a retrieval-based Q&A chain
    qa_chain = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=vectorstore.as_retriever(search_kwargs={"k": 3}),
        memory=memory,
        condense_question_prompt=None,  # use default for now, or customize
        combine_docs_chain_kwargs={"prompt": prompt},
        verbose=True
    )

    return qa_chain

def main():
    # 1) Load the ebpf documentation from file
    doc_path = "ebpf_docs.txt"  # Path to the text file with the ebpf docs
    ebpf_text = load_ebpf_docs(doc_path)

    # 2) Build a FAISS vectorstore from the ebpf docs
    vectorstore = build_vectorstore(ebpf_text)

    # 3) Create the generative agent (ConversationalRetrievalChain)
    agent = create_agent(vectorstore)

    # 4) Example conversation loop
    print("ebpfDocBot is ready to answer your queries about ebpf!\n")
    print("Type 'exit' or 'quit' to end.\n")
    while True:
        user_input = input("You: ")
        if user_input.lower() in ["exit", "quit"]:
            print("ebpfDocBot: Goodbye!")
            break

        # 5) Pass the user input to the agent
        response = agent({"question": user_input})
        print(f"ebpfDocBot: {response['answer']}\n")

if __name__ == "__main__":
    main()
