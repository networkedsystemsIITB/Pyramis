# --- End-to-end example demonstration
1. Working pyramis tranlator package
a. Obtain pyramis source-code, install pyramis on your machine, close the pyramis directory.
- Pyramis source code will be stored at github::synerg5g/pyramis
---> git clone will download pyramis/, which contains the setup.py script (pip installation instructions), and pyramis/pyramis/ which contains the core translator source code.

- venv installation
---> create a venv .pyramis in the source directory, activate it
---> for dev, need to add the _/local file to PATHT.
---> Navigate to the directory containing `setup.py` and run `pip install -e .` [TODO: check installation in a venv, no sudo]

- Pyramis can now be used via the command line to perform translation.
---> See `pyramis --help` for a list of valid options and their respective actions. 

b. Create a directory <multitier-system>, define system-interfaces.json file in multitier-system/

c. Create a subdirectory for each NF you want to specify. Define `udf.cpp`, `udf.h`, `<NFName>.dsl
- udf.cpp, udf.h contain custom helper functions that are called by the pyramis UDF keyword. 
---> At minimum, they must contain definitions of encoders and decoders corresponding to the application protocol your NF wishes to adopt.
---> By default, pyramis provides a library to encode and decode http messages. [invisible to user]
---> pyramis also provides a library to encode and decode ASN messages used extensively in 3gpp communications. [invisible to user]

- <NFName.dsl> is written according to the pyramis syntax rules.
---> Rules will be described in the readme in the github documentation.

NF folders now have sufficient information for a successful translation to C++
- Any common auxilliary files required by the translator will be stored in a hidden directory, separate from the cwd on installation. [invisible to user]
- NF-specific auxilliary files generated during translation will be stored in a hidden per-NF folder on the same machine [invisible to user]

d. Trigger translation 
- pyramis translate <NFName>, pyramis build <NFName>, pyramis run <NFName>
---> Translator must be run from the parent multitier-system/ directory (that contains the <NF_xxx> subdirectories.
---> NFName must be present in the system-interfaces.json file. [TODO: enforced by the translator].

- Newly generated files will be stored in NF-specific subdirectories of multitier-system/__<PYRAMIS_COMMAND>__/ folder.
> __TRANSLATE_RAW__: Contains raw 
---> Each __TRANSLATED__/<NFName>/ directory will contain: <NFName>_linking.cpp, <NFName>_linking.h, <NFName>_contexts.h

> __BUILD__: Contains all necessary files required to compile and run an instance of your multitier system.
---> Each __BUILD__/<NFName>/ directory will contain: <NFName>_linking.cpp, <NFName>_linking.h, <NFName>_contexts.h (+) <NFName>_platform.cpp, <NFName>_platform.h (+) udf.cpp, udf.h (+) MAKEFILE
---> note: pyramis will generate a base MAKEFILE for compilation. However, it may need to be modified if you use external, non-default pyramis libraries.
---> Include paths in all files in __BUILD__ will be generated appropriately. This is required as dependence on an application-layer protocol is almost guaranteed in any multitier-system. [TODO: appropriate include paths]

e. Run the NFs via the pyramis interface.
- pyramis run <NFName> <num_threads>
--->  run the MAKEFILE for the specified NF, store the executables in the /__RUN__/<NFName>/ directory.
--->  run the newly generated executable - NF is now running. (using common platform file structure)

The final directory structure visible to the user (for a single pyramis NF) would be
multitier-system/
		- system_interfaces.json # by user
		/<NF_xxx>/ ## original folder, written by user. All other folders are generated.
			  - <NFName.dsl>
			  - udf.cpp
			  - udf.h
			  - <NFName>_interfaces.json ## generated.
		/__TRANSLATE__/
			       /<NFName>/
				   - <NFName>_linking.cpp
			   	   - <NFName>_linking.h
			           - <NFName>_contexts.h
		/__BUILD__/
			   /<NFName>/
				   - <NFName>_linking.cpp
				   - <NFName>_linking.h
				   - <NFName>_contexts.h
				   - <NFName>_platform.cpp
				   - <NFName>_platform.h
				   - udf.cpp
				   - udf.h
				   - MAKEFILE
		/__RUN__/
			/<NFName>/
				   - <NFName.exe>
		
				  
				  
				  
				  
				  
				  
				  
				  



