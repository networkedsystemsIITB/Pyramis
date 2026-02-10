perf record
perf report

For tcp, tcp_write_xmit() in kernel is responsible for sending segments.  
will run as long as there is congestion at the 



# Pyramis Timers
For each user, your NF can implement the same, finite set of _e_timer_type, each with an associated expiry callback.
users are identified via the <keygen> procedure_key.
- i.e., a user can have [num timer types] active timers at the same time, one of each kind.

for a single threaded NF,
In the linking.cpp, timer_start and timer_stop will be called for a specific procedure_key only. Hence
timer_start and timer_stop must be passed the _e_timer_type to be started/stopped. translator will 
implicitly add the procedure_key dependency during codegen.

- One timer_expiry_ctx per callback.
- one callback per timer_type
- one timer_expiry_ctx per timer_type
- one timer_expiry_ctx per timer.

timerfd of each started timer is added to epoll watchlist of this nfvinst.
function pointer to the callback is stored in the fdData_t at timer_start.
TIMERFD_SOCKET is added to the fdmap of event socket as fdData_t{}


### A. union of timer_expiry_ctx structs
- one timer_expiry_ctx_t per timer_type.
- CREATE_TIMER_CONTEXT(__ident, __timer_type) # __timer_types specified in json.

### B. template class Timer
Timer<_e_timer_type T> Timer(timer_ctx)

usage:
// create a timer_ctx object

// pass intoo timer constructor


I imagine
timer_expirty_ctx_type_a {..some definition}
timer_expiry_ctx_type_b {...some other definition}

timerCB needs to be templated.?
### timer_ctx needs to be a template class?
- from platform, 
auto timer_ctx = socket_fdd_itr->second.timer_ctx;
socket_fdd_itr->second.timerCB(timer_ctx, nfvInst)



CREATE_TIMER_CTX(my_context, ?timer_type?) # arguments for the callback.
SET(my_context, user_id, userID)
TIMER_START (MACRO(T_LOGIN_FORGET), 5, my_context, forget_user) // TIMER_START (__timer_type, __timeout, __expiry_context, __callback)
*---
timer_expiry_context_t my_context {}; # create_timer_ctx
my_context.user_id = userID; # set

// TIMER_START
// my_context.timer_id = args[0]; # "timer_id" is default attribute for all timer contexts.
mycontext.timer_id = <keygen> # the procedure_key variable.
mycontext.timer_type = __timer_type # one of the _e_timer_type 
generic_timer_start(my_context, 5, &forget_user, nfvInst);


void generic_timer_start(timer_expiry_context_t& timer_ctx, int timeout_sec, void (*callback)(timer_expiry_context_t& timer_ctx, struct nfvInstanceData *nfvInst), struct nfvInstanceData *nfvInst) {
    // create timerfd, add to epoll of nfvinst.
    ```
    int tfd = timerfd_create(CLOCK_REALTIME, 0);
    struct itimerspec new_spec = {
    .it_interval = {0,0}, // .tv_sec, .tv_nsec. interval for periodic timer, after first expiry
    .it_value = {timeout_sec, 0}     // .tv_sec, .tv_nsec. the first expiry period
    };

    // _utr == new_value, _otr == old_value
    timerfd_settime(tfd, 0, &new_spec, NULL); // timer started

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = tfd;
    epoll_ctl(nfvInst->epoll_fd, EPOLL_CTL_ADD, tfd, &ev);

    fdData_t timer_fdd = fdData_t(TIMERFD_SOCKET, tfd);
    timer_fdd.timer_ctx = timer_ctx;    // always
    timer_fdd.timerCB = callback; // always

    // store timerfd in fd_map
    nfvInst->fd_map[timer_fdd.fd] = timer_fdd; // gen
}
    ```

// TIMER_STOP(__timer_type)
// ...
// get the timer_ctx from map
// ctx = timer_ctx_
generic_timer_stop(timer_type, nfvInst)
```
void generic_timer_stop(<type> __timer_to_stop_type, timer_expiry_ctx_t& ctx, struct nfvInstanceData *nfvInst) {
    // get timer_ctx from __timer_id via timer_context_map
    ctx = timer_context_map[__timer_id];

    // locate timerfd with id procedure_key and timer_type ctx.timer_type

}

```

stopping a timer with a given id:
a. Storing timer contexts in a seperate map, keyed by timer_id
in timer_expiry_context_map:
std::map<timer_id, timer_expiry_context_t>

- timer_expiry_context_t contains fixed attribute names for each timer-id.
- these attribute names can then be accessed by the timer callback.
