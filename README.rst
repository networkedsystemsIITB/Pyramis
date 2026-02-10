**Pyramis** is a Domain-Specific language that enables you to specify multi-tier systems of variying complexities with minimal ambiguity:

#. **Specify** the nodes of your multi-tier system.
#. **Analyze** each node specification to ensure validity under Pyramis rules.
#. **Translate** each node specification to a C++ Network Function (NF) implementation.
#. **Run** each NF implementation as a multithreaded process.

⚙️ Installation
============
At present, Pyramis can only be installed from source.

PyPI (Python)
-------------
.. code-block:: bash

   pip install git+https://github.com/armaanchowfin/pyramis.git

⚡️ Quick start
===========

#. **Install Pyramis**

.. code-block:: bash

   pip install git+https://github.com/armaanchowfin/pyramis.git


2. **Analyze, build and run the login-server NF**

.. code-block:: bash
   
   cd pyramis/examples/login-server
   pyramis build NF_A
   pyramis run NF_A 1

3. **Run test client to verify** 

.. code-block:: bash

   cd pyramis/examples/login-server/Client
   make
   ./build/client



🕹️ Using Pyramis
=================

First, **create your Pyramis specification**

   Please read our `Pyramis Keyword Reference <docs/pyramis-keywords.md>`_ for tips on writing Pyramis specifications

- Fix names and interfaces of individual nodes, define ``interfaces.json``.

- For each node, use Pyramis keywords to define a processing file ``node_name.dsl``. 

- UDFs, if any must be consolidated into a single ``udf.h``, ``udf.cpp`` pair. 

- Custom protocol headers, if any, must be in `utils/`

Next, navigate to the root directory of your project and **run Pyramis commands as necessary**

+-----------------------------------------------+-----------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
| Task                                          | Command Line                                                                                        | Result                                                                      |
+===============================================+=====================================================================================================+=============================================================================+
| Validate Pyramis Specification                || ``$ pyramis analyze NF_A``                                                                         || The Pyramis Compiler will generate an error-report for any irregularities  |
+-----------------------------------------------+-----------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
| Build C++ Implementation                      || ``$ pyramis build NF_A``                                                                           || A set of .cpp and .h files will be generated along with a base Makefile.   |
+-----------------------------------------------+-----------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+
| Run C++ NFs                                   || ``$ pyramis run NF_A num_threads``                                                                 || Your NF specification is now a running NF instance                         |
+-----------------------------------------------+-----------------------------------------------------------------------------------------------------+-----------------------------------------------------------------------------+

   Run ``pyramis --help`` for the list of supported Pyramis commands

💡 How Pyramis works
==================

   Please read our `Pyramis Developer Reference <docs/dev-docs.md>`_ for a more detailed treatment.

The Pyramis Compiler is developed to demonstrate that Pyramis is a complete and flexible language.

- By showing that a path exists from Pyramis specification to a correct implementation, (in our case, via a compiler), we provide evidence for the correctness of Pyramis as a specification language.

