# GreenFuzz 
This is a tool containing a fake socket library named desock+ and a tool name ASE for extracting error-prone system-calls and their arguments. 
By using these tools, one can use a fuzzer and send the inputs to the software under tests such as network protocols with out the need of sending it through the network stack. 
# Build
`make`

# Usage
By using the LD_PRELOAD environment variable:

`LD_PRELOAD=/path/to/desockplus/desockplus.so ./afl-fuzz -d -i testcase_dir -o findings_dir -- /path/to/program [...params...]`
