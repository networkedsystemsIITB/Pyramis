# NF State
State is used as an indicator of NF procedure status, specifies the appropriate message handler for a new message.
- Pyramis NFs define a `state` that is part of UEContext, stored in `UEContextMap` <amfuengapid: struct UEContext>
---> `amfuengapid` is assigned to a UEContext and stored in the NF `UEContextMap` on receipt of the first NGAP Registration Request message
via a UDF.
- Since a single message receipt on AMF can be handled by calling a chain of events, this state becomes a reference to the original handler for the current message.
---> `state` remains constant between message receipt and the next message send.
---> `state` is set immediately before SEND.
Eg: nrfDiscovery -> ueAuthentication -> ueAuthenticationUpdate -> nrfDiscovery -> uecmRegistration -> udmsdmget -> X (~ sbiState)

# .dsl setup
Two message handling classes: one handles uplink messages from RAN and processes based on the procedurecodeIE in the RAN->AMF message, the other handles messages from the other sbi based on an AMF-defined 'UE state'.

Q. Is it possible to represent this message handling more generally, based on a single definition of state to drive message processing at AMF?

# Support for a Timer


2. Timer usage
===============
START_TIMER(name, timeoutsec, callback)
- name: An identifier of the timer type. (eg: T350)
- timeoutsec: the duration of the timer
- callback: the action to be carried out by the NF if the timer expires.

STOP_TIMER(name)
- name: An identifier of the timer type. (eg: T350)

The spec writer will specify a START_TIMER(name, timeoutsec, callback) at some point in the node processing flow anytime they want to indicate the establishment of a timer.
STOP_TIMER(name) is specified when the spec writer wants to indicate the disabling of a timer.


3. Timer Implementation
========================
The Pyramis timer implementation uses the timerfd API and epoll API.

* Under what conditions to execute the callback?
-------------------------------------------------
Callback for a particular timer must be executed any time the timerfd generates an expiry notification.
a timerfd will generate an expiry notification if:
- a duration of time > timeoutsec has passed, and the timer has not been disabled.
- a timer is disabled manually. (indicated by STOP_TIMER, implemented via timerfd+ epoll)

* Approach 1: timerfd_demo.c
-----------------------------
amf-linking.cpp processing has 2 entry points, based on the port at which the NF i.e. platform received the latest message. `sbiIncoming` for messages from other NFs, `NGAPIncoming` for messages from RAN (i.e. UE)

Assume we are at some intermediate stage in the NF processing flow.
- Control is currently in event A of the amf_linking.cpp file
- We reached here from the platform file via the `recvandprocesscallbacks()`  that called the appropriate function pointer via `fdtoresponsehandlermap` or `fdtorequesthandlermap`, (these were setup during NF init using the provided function names in `porttohandlermap`). -> sbiincoming or ngapincoming.

In terms of implementation logic, "stage of program flow" is expressed via the `uecontext.state` attribute, maintained for every UE in the UEContextMap, stored in `UEContextMap` <amfuengapid: struct UEContext>
---> `amfuengapid` is generated via a UDF for each new UE and stored in the NF `UEContextMap` in the `struct UEContext` on receipt of the first NGAP Registration Request message 

Assume event A is about to send a message via the SEND -> senddata() function, and the spec writer wanted to express the following timer condition:
"In NF state s', the outgoing message must receive a response back from its peer NF in <=6 seconds. If the response is not received in that timeframe, retransmit the previously sent message."
- To specify this, the spec writer would do two things:
1. START_TIMER() as soon as the outgoing message has been sent, i.e. in the same EVENT.
2. STOP_TIMER() just before/on entering the EVENT that is meant to process the expected response. 

To implement this, we must:
1. Initialise a timerfd.
2. Register this timer with an epoll fd via `epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)`
- epfd: The "monitor" fd.
- op: what to do with the fd. `EPOLL_CTL_ADD` to add an fd to the interest list of epfd.
- fd: the fd that needs to be monitored by the "monitor" i.e. epoll fd.
- event: A struct to specify `event.events` -> EPOLLIN : epfd can be read from
                             `event.data` -> user data that needs to be linked  to epfd.

On timer expiry, the expiry notification will be stored in the epollfd waitqueue in the kernel.
- Until `epoll_wait` is called on the epollfd, the timer expiry will not be visible to the user-level application.




Possibilities: 
a. as per timerfd_demo.c (OR)
b. modify platform file.



# debug infi recursion
['datatypes.h', 'setup.h', 'aka.h', 'platform.h', 'logging.h', '_5gmmMsgApi.h', '_5gsmMsgApi.h', 'nasLogging.h', 'cryptUtil.h'] - extendedprotocoldisctriminator_t 

- need to include typedef <t1> <t2> as structs

