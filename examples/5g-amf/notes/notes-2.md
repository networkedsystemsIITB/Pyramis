references
----------
1. https://realpython.com/command-line-interfaces-python-argparse/#getting-to-know-command-line-interfaces
shedskin:
- A Pyramis class that stores gx i.e. globalinfo
- a GlobalInfo class that stores reference to the "python module" being translated.
- a python "Module" class that has a reference to its AST i.e. the result of source.parse

0. translator.setup: parse utility headers and store in gx.asn_base_types as dict of symbol-trees,
1. translator.analyze: // pyramis->py, use .py to create "Module + AST", 
2. infer.analyze    // walk down the pyAST, creating a scope tree with types as well as a data structure that can be traversed for subsequent printing. (do dataflow graph on a seperate branch.)
3. cpp.generate_code : // c++, linkingH + contexts.h, platform.c++.

branch: master
---------------
a. graph.parse_module() will create the "module" and its AST. the module (i.e. AST) + globalinfo will be used subsequently by infer.analyze() to 
perform the AST walk while updating the **scope tree**.

branch: dataflow analysis
------------------------
@30/3/24
todo: create ModuleVisitor class, assoc mv with the module object, 
create Function class, check if funcdefs are being stored along with string args.
define the ast walk for visit_Module and visit_functionDef.

#--- infer.py has the details of type propagation. A CNode (ConstraintNode) could be a "thing" with type python.variable or python.Function?. Typestrs would "flow" through the generated constraint graph.

#--- *args in the ModuleVisitor class ast_utils
- Each Function/Call node has a reference to the global ast visitor. What does this enable?
given an AST, we define a ModuleVisitor. We define a global reference to that visitor.
Note: functiodefs have a retnode and yieldnode CNode? (func.retnode)

# --- CNodes
A CNode is created at every ast node. It contains a ref to its ast node, a ref to its parent functiondef and a ref to the global context.

# --- Function in python
A Function's associated (ast) node is always a Functiondef. For Pyramis, the node is an invariant.


# --- ModuleVisitor (graph.py)
Every python.Module has an associated modulevisitor that implements ast walk and creation of python.XXX objects.
A global modulevisitor object tracks current state during the walk.
1. Make a record of all the pyramis events i.e. functiondefs at walk init, along with the formal arguments passed in.
- events as python.Functions, arguments as list of arg strings.
2. subsequent visit_Functiondef builds python.Variable objects for each function param. 

## If/Else handling
- By default, nodevisitor only visits level-0 for loops.
- visit_expr contains ast.Compare, ast.Call, ast.Yield.

# --- Shedskin's python.Module
Shedskin seems to parse atleast builtin.py before beginning the amf.py walk.
- builtins.py is a file with pure python class definitions to represent the allowed variable types. 
- parsed to a python.Module with several python.Class objects embedded. (when??)
1. The neat trick
- Simulate a "from * import builtin", and PARSE that imported file (create a module) using the modulevisitor
before continuing the modulevisit walk of the original. 
2. implemnted by: 
- visitor that was called by module test.py ka visit_module() creates an importfrom node and visits that node
- the visit_importfrom() eventually calls parse_module() on this imported file
- the regular parse_module() begins the walk of this builitins.py file, finally storing it in the gx.modules.
- once the buuilins parse is completed, this parse_module() is popped off the stack, and the visit_module resumes the original parse 

# --- Python types
All function call arguments terminate at a visit_Constant(). Here, shedskin associates a set of possible types with
the ast node, (in this case the ast.Constant representing a ast.Call argument i.e. a Pyramis ACTION argument.)
- in shedskin, types are assigned to the string literal ast.Constant.value by the python() compilers in-built type assignment mechanism.
- Python stores its types as classes in stdlib/typeshed/builtins.pyi

# --- Thinking about Types in pyramis.
1. Dynamically generating the custom type-class file that represents each struct encountered in the header-file parse. 
- If possible, provide the supported asn_base_types along with the pyramis package itself! (lke python). <see readme.md#functionality>
- Provide the ASN parser source, so people can extend the basetypes set.

- Nested scopes allow the existence of multiple definitions of the same variable name, by enforcing scope-locality of those variables.
Q. Should this be allowed? 
-> If inner scope types a variable (by explicit create_message or udf) with same name as one in any enclosing scope, variable redefinition, modify the old variable object.
-> else, do nothing
Default actions: If same name used in current scope, new usage will modify the type of the same variable object.
--- Different scopes may contain variables with same names, but they must all refer to the same object, created in a different scope.

2. Typing Invariants:
======================
- All event i.e. python.Function() formals have python type "str" at init.
- If an ast.Constant.value is a udf name, the subsequent args are assigned types from their udf declarations in gx.udfs. (in visit_constant, check if arg[x] is in gx.udfs. If yes, type from udfs)
- If an ast.Constant ka action is CREATE_MESSAGE, assign type from arg.
- std::vector and fixed size C arrays are treated as 
type = value type, thing = ARRAY
--> int **x is treated as an int with indirection level = 2

Pyramis Invariants
-------------------
1. Single python.Variable object, "stored" in scope symtab. All other
objects maintain references to the single instance and can update it at any time. (variables in scope tree may be untyped for certain durations)

2. All variables in scope tree must be typed after first ast walk.

3. Between CALL Action and python.Event(), only one must create new variables.

4. All Python.Variables() must be stored in a class Scope, and each python.Action and python.Event contains a reference to its enclosing scope. (EVENT/IF/ELSE) and therefore the (eventually) typed variables.

5. Each variable has a parent, i.e. the pyramis.Action that contains it. Further, any 
python.variable encountered in an action must be stored in the appropriate scope.

6. CALL action variables must always be typed in visit_Call(). 
On visit_Functiondef, if the variable untyped after get_variable -> CALL occurs in a different event
On visit_Functiondef, if variable typed after get_variable -> CALL occurred before, was recorded. (by the search-in-calls pathway.)
On visit_Call, if action == CALL, if variable untyped after get_variable -> ??
--> Need to link the variables of events to variables of calls somehow
EVENT entry(a, b, c):
    CALL (eventname, a, b) # stored in mv.calls as a python.Action(), formals [] = a,b

EVENT eventname(j, k): 
- get_variable() should search for python.action in calls, return ref variable with same idx.
- In the current event scope symtab, store j: <var from call>, k:<var from call>
subsequent non-CALL access to j,k in the current event should assign a type to j,k -> i.e. 
curr_scope.symtab[j].type = type --> old_scope.symtab[a].type = type

    # Use j, k in a type-assignment action
    - Giving j, k a type should automatically give a, b in the different event scope a
    type.
    


On visit_Call, if action == CALL, if variable typed after get_variable -> assertion, always true.



- EVENTs are list of Pyramis Actions.
- EVENT is rep via a python.Function object.
- Every Action has an "action". and set of user attributes with Python.Type().

# EVENTs are list of Pyramis Actions.
# EVENT is rep via a python.Function object.
# Every Action has an "action". and set of user attributes with Python.Type().
# 
# Sometimes a type cannot be assigned to an identifier before the first visit to its
# enclosing action.
#  --- in this case, store ref to the attribute in untyped attr list stored in the Action.
#  --- Also store refs to all Actions that are yet untyped in the global/scope context.
#  --- while traversing the current scope, keep updating the symbol table.
#  --- At exit from the untyped scope, for each untyped attribute in each untyped EVENT,
#  --- look for the attribute in symtab, and assign a type to the Action if found.
#  --- if not found, raise an incomplete type error to errorlog.
# 
# only UDF, CREATE_MESSAGE, SET_KEY can assign concrete types to attributes.
# other actions (SET) must be checked for consistency with previously assigned types.
# --- SET can also be used to assign type :if the base attr of the lhs (lhs.split(.)[0])
# --- is in the symtab of current or ancestor scopes, and variable on rhs is untyped in
# --- scope, assign the type of rhs. (if char * make ?? <char> or string)
# - See get_variable etc. in infer.py
# 
# per-action processing is definitely needed in visit_Call()
#
# KEY INVARIANT: Single python.Variable object, "stored" in scope symtab. All other
# objects maintain references to the single instance and can update it at any time.
# called from platform file.

2. Python types (int, bool, float etc.) are all implemented as Classes in stdlib/typeshed/builtins.pyi
- types are defined as a large set of methods that can be performed on them. (this set should be significatly smaller for pyramis types) 
- these type classes have a list __subclass__ that could potentially store heirarchical Pyramis classes.

3. All ast.Call i.e. pyramis action arguments are interpreted as class `str` by python's type().

# --- Implementing the ASN header-file parser
1. Parse the set of header files generated by the asn1.c compiler
- i.e. create a file in .deps/basetypes.py that represents 
each struct in each header file as a class with subclasses for nested types.

2. Consider using an intermediate struct-dict in "contexts.py"
- each base struct forms a class.

4. Supported message-types

# --- Application-level timers in Pyramis
There can only be one active timer of a particular type at a time.
TIMER_START(__timer_type, __timeout_sec, __callback)

TIMER_STOP(__timer_type)
- unique key must be associated with each instance of a procedure -> to assign synchronous order given asynchronous message receipts.
- If multiple timer_start at the same timer in the same event, unique tfds will be  assigned to each timer instance, and each will have a seperate entry in the fd_map as well as be independently tracked by the server epoll instance. 
- To stop a timer involves:
a. retrieve the appropriate tfd.
b. timerfd_settime = 0 on the tfd.
c. close the tfd (i.e. remove from epoll), delete from fd_map.

//@@timer
EVENT callback(__timer_context)
In a timer event, the function signature args are converted to 
// timer_ctx attribute accesses before any other code is generated.
EVENT forget_user(userID, timer_id) -> void forget_user(timer_expiry_struct_t timer_ctx, struct nfvInstanceData *nfvInst)
- CONSTRAINT: The pyramis args must exactly match the set of valid timer context attributes.

# --- Codegen for timer
TIMER_START(<timerID>, <>)

# --- Vocabulary for Pyramis multi-tier Systems
1. Procedure: A series of messages sent-recd by this NF, terminating with a final response to a sink NF from which no response is expected
2. Request: A message sent from this NF to a peer NF such that this NF expects a response from the peer. Pyramis indicates a request by specifying the handling of the subsequent response via the `callback` argument of the SEND statement. 
3. Response: SEND without a callback.

A SEND without a callback signifies the end of a (sub)procedure call-flow.

# --- Generalised Pyramis NF architecture
A multitier system is specified in terms of its global NF architecture, its own interfaces and the processing actions to be performed on message receipt at any of own interfaces.
- Interface: specifies networking configs and peer NFs that communicate with it. This is represented via a per-NF interfaces.json file
- Global NF architecture: specifying all NFs and their interfaces. Union of the interface.json files of each NF. Represented by a single system-level system-interfaces.json file.
- Processing actions: specified via the pyramis keywords in the .dsl file. 

Requirements for compilation to an implementation
-------------------------------------------------
On its own, a Pyramis specification provides sufficient information to communicate the key aspects of the multi-tier system. However, 
to compile to a working implementation, certain requirements must be met:
1. The NF implementation must adopt a platform - processing architecture, where a platform file triggers kernel networking actions, and the processing
file performs user-level actions. 
- In the current implementation, the processing.dsl file is translated to C++ to play the role of the user-level processing file.
- In the current implementation, a multithreaded, asynchronous epoll-based platform.cpp file is provided that contains an entry point into the user-level processing. 

2. Application-level protocol and corresponding codecs must be well-defined
The following assumptions are made about the implementation of the application-layer protocol used by the NF.
- Valid messages for custom protocols must be implemented as complete C/C++ structs.
- HTTP messages must represent and access their payload strings as attributes of nlohmann::json objects. We provide an HTTP library for this purpose.
- All char arrays are interpreted as C++ std::vectors, and strings as std::string objects. Strings, if any, must be null-terminated.

3. The NF must generate a unique call-flow identifier for each instance of procedure it supports.
Procedure may be simple (login request-response) or complex (SMF session-establishment). Complexity arises due to the requirement of 
demultiplexing messages received at a single interface to the appropriate message handler.
- The notion of "key" and its supporting fd_to_key_map and key_to_fd_map are implementation-specific constructs. `key` + NF `state` are used by the 
NF application to maintain a synchronous message-processing flow despite asynchronous message receipt.
- -A single NF independently initiates procedure requests.

Therefore, the prescribed initial directory structure of a multitier-system after installing pyramis as root is:
/my_multitier_system
    /NF_1
        - interfaces.json
        - NF_1.dsl
        - udf.cpp # dependent on utility_lib
        - udf.h
        - Makefile # for compilation of generated code.
    /NF_2
    /NF_3
    /utility_library
        - <Collection of .h and .cpp files. NF .dsl, udfs, platform file are dependent on these libs>
    - system-interfaces.json

i.e., a seperate directory for each NF, all stored in a parent directory.

To translate a particular node, navigate to /my_multitier_system and do `pyramis <NF_name>`.
The final directory structure should resemble:
/my_multitier_system
    /NF_1
        /.deps
            /stripped
                - <header files from utility_library stripped of comments>
            - NF_1.ast
            - NF_1.py
        - interfaces.json
        - NF_1.dsl
        - udf.cpp # dependent on utility_lib
        - udf.h
        - Makefile # for compilation of generated code.
        * linking.h
        * platform.cpp
        * contexts.h
        * <NF_name_linking.cpp>
    /NF_2
    /NF_3
    /utility_library
        - <Collection of .h and .cpp files. NF .dsl, udfs, platform file are dependent on these libs>
    - system-interfaces.json


# --- Pyramis type_of() method
Meant to be analogous to python's type(). Uses .deps/basetypes for assistance.
1. How does Python implement type()? -> just check builtins.py?
- 
- given an argument string, need to associate it with a set of pyramis basetypes?

a. finalising the pyramis workflow
b. modifications to translator -> SEND























- In Pyc compiler, _ste have a pointer to scope. scopes are not the container.

Issue: 
a. Pyramis Code SET accesses attribute AMFName of the amfconfig.json file to set a live program symbol. JSON File contents are made available to the program by READ_CONFIG command that initialises a Reader (a reference) for the JSON file in argument. In pyramis, attributes of the json file are subsequently accessed via dot notation. 
What does type-checking mean here?
- amfconfig is of type "whatever json file it was given"? READ_CONFIG performs make_json_tree() with amfconfig.json as context_dict.
-make_type_tree() is used for handling asn types.
-> messagetypes i.e. asn_base_types should only contain the parsed C header files.
-> JSON files should be stored as 

b. Preliminary dataype parsing, in particular JSON and HTTP. 
- jsonmessages.json is created by the spec designer. These are non-asn messagetypes but are specified by 3gpp. Is asn compiler <-> 3gpp?
Compiler takes jsonmessages as a given. How are HTTPrequests and json messages different? or are they the same?
Explore loading config.json into context by READ_CONFIG instead of pre-init.


In arch.json, Node [] is the list of nodes that send to the named interface of the current node.

In NRF, the nnrf interface receives from nodes [AMF, SMF].
The Nnrf interface of NRF has port: 65535 ...
The sending node (AMF)specifies a callback function

In AMF entry.
Interface N2 has port number 38412. It recevies message from [RAN].

Pyramis AMF spec only describes messages SENT by AMF. 


1. Sender is always self._params[2].
2. destination node: self._params[3], interface = self._params[4].

if self._params[3] == "RAN":
send (amf, ram, n2, NULL): send a message from n2 interface of AMF to ran. (from node b4 to node)
- send to ran will always replace AMF, N2 with its own details
get_port_protocol(self.params[2], self._params[4])

ALL OTHER TIMES
else:
    get_p_protocol(self.params[3], self._params(4))


SEND(amf, nrf, Nnrf, cbf) : send a message from AMF to interface Nnrf of the nrf node. Therefore, replace sending node (AMF) and receiving interface (Nnrf) with Nnrf details
- port 65535 etc.

SEND(amf, ausf, nausf): send from amf to nausf interface of ausf.
ausf entry in arch should have sending node (AMF) in its Nodes[] as a semantic check.
replace sending node (AMF) and recieving interface (nausf) with nausf details.


EVENT initialRegistrationRequest(messageBody, nasMsg)

    UDF (status1, ngapGetRanUeNgapId, ranUeNgapId, messageBody)

    STORE (UeContextMapTemp, ranUeNgapId, _5gregType, nasMsg.plain._5gmmMsg.regReqMsg._5gregType)
    STORE (UeContextMapTemp, ranUeNgapId, ngKsi, nasMsg.plain._5gmmMsg.regReqMsg.ngKsi)

Issue: store will not detect nasmsg type from event context.
add to get_symbol: 
Find the first_block_ancestor_scope of the CALLScope whos expr.name == current event name.
- 1. Traverse entire scope tree to find a particular call scope with some expr.name, return a ref to get_symbol. if scope not found?
- 2. symbol = ref.get_first_ancestor().get_symbol_from_scope(symbolname)
- 3. return symbol.
search for the symbol in that scope, and return it to caller.
current event name

We ideally want event type assign to assign to the event params and scope as soon as the event is accessed.
Cannot avoid the event-definition-before-event-call condition
If an event is reached:
- A new event scope is created with parent as globalscope
- an event expr is created, pyrmis params are read and stored in header.linked to scope.
- expr.type-assign() occurs.
    - For each param in self._params, get_symbol().
    - ?not necessary? get_symbol does a persistent-scope-tree-wide search for the symbolname as described above 1.-3.
    - If the call scope not found, can return NO_TYPE_YET from get_symbol.
    cppfunction (type_assign) checks no-type-condition
    - if true, mark the event-scope as failed, subsequent usage of event symbols will have NOTYPE. (all params including defaults will be stored in event scope)
    - Walk continues, until the first CALL to a failed event is made. Will this CALL to an event always have non-NOTYPE params? YES. Enforce this via the typing rules.
    - If K_CALL: after type_assign(), in pyanalyzer 
    for eventscope in globalscope.children:
        if expr.name == event.fname:
            failed_event = eventscope.event
            failed_event.update_types(current)
            eventscope.is_event_failed = False # was set to true by get_symbol result in first (original) EVENT
            # get_symbol does not require a persistent serach. all subseq
            params will infer type = NOTYPE from event scope as usual.

this update_types() is of the following form:

in pyramisevent:
- IRCM.currentscope = CALL scope.
def update_types(self):
    call = scope.expr
    # swap types: for param in zip ...
    event.add_params_to_scope()
    for call_ in self.calls:
        call_.update_types()

in k_exprs:
def update_types(self):
    if self is FOR/IF/ELSE:
        self.type_assign()
        for call_ in self.body:
            call_.update_types()
    else:
        self.type_assign() # updates self.parameters.

2 pass solution:
- move to new event if failed event occurs in pass 1.
- only update the event params subsequently.
- event.calls will have some notypes.


- exit first walk, do second_walk(IRC)

for eventscope in head.children:
    if scope.failed:
        event = scope.expr
        event.update_types()
OR

- Updates cppfile directly.
for event in file.events:
    if event.scope.failed:
        event.update_types()

in pyramisevent:
def update_types(self):
    for call in self.calls:
        call.update_types()

in k_exprs:
def update_types(self):
    if self is FOR/IF/ELSE:
        self.type_assign()
        for call_ in self.body:
            call_.update_types()
    else:
        self.type_assign() # updates self.parameters.
    



    Q. Are calls a flat list and only scopes show nesting?
    - No. IF, FOR, ELSE expr have body[] of k_expr.

- THE ABOVE FLOW checks if a CALL is calling a failed event at every CALL occurence.
- If yes, 
GET_SYMBOL persistent_tree_search not required.
event params would just be given NO_TYPE YET on first visit.
- Might be more efficient to only update a symbol when it is looked up (i.e. via get_symbol persistent.)


LOGGING:
- Set up in new module and import to all?
https://docs.python.org/3/howto/logging.html#
- basicconfig must be set up in pyparserdriver i.e. main()
```
def main():
    logging.basicConfig(filename='PyramisCompiler.log', level=logging.DEBUG)
    logging.info('Started')
    # call functions in diffrent modules. Each module must have logging imported.
    logging.info('Finished')
``` 
I need filename info in log messages.
------------------------------------------------------------
Ref: https://github.com/shedskin/shedskin for frontend.

Scopes only store pointer to their respective expression. (via keyword_expr, if_expr...etc). These point to the expr objects that are subsequently stored in the cppfile.

TODO:
1. Context must store type-trees of asn_base_types before first AST walk. Make get_symbol purely a scope-tree parent walk, i.e. if symbol not in current, search parent. 
2. Enable usage as package. Workflow: Import Translator into a python script that has access to all NF specifications. Run the translation script to generate code for 
the desired subset of nfs.
--> __init__.py contains code to run on importing a module.