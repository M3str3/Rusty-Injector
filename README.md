# Rusty-Injector
Useful tool to inject shellcodes on PE (Portable Executables)
Building.....

Example use: cargo run --release .\example\helloworld\hello_world.exe hola.exe shell.txt
Then, the program generates an output file named out/hola.exe, injecting the shellcode into a new section of the PE file and redirecting the entry point to this newly added section.