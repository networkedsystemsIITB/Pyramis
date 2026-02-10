A simple test client to demonstrate the working of the Pyramis generated login-server program. 
Note that the client is independent of any specification and is implemented purely as a test program.
- In particular, encoders and decoders are defined in synerp_messages.cpp  instead of udf.cpp to 
re-iterate the difference.

`make` then `./build/client` to run.