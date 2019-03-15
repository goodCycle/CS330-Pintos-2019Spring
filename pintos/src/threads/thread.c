#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

#include "threads/fixed-point.h"
#include "devices/timer.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif


/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;
static struct list sleep_list; //
extern struct list wake_ticks_list; //
struct list all_list;         /* list of thread running, ready, blokced */

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

//
static int load_avg;

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.
   Also initializes the run queue and the tid lock.
   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().
   It is not safe to call thread_current() until this function
   finishes. */

/* This is 2016 spring cs330 skeleton code */

void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&sleep_list); //
  list_init (&wake_ticks_list); //
  list_init (&all_list); //

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  // printf("initial_thread->tid : %d\n", initial_thread->tid);

  //
  load_avg = 0;
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
  
  if (thread_mlfqs) {
    struct thread *curr_thread = thread_current();
    if (timer_ticks() % TIMER_FREQ == 0) {
      //printf("In Update curr->recent_cpu\n");
      calculate_load_avg();
      struct list_elem *e, *next;
      // printf("all list size %d \n", list_size(&all_list));
      for (e = list_begin(&all_list); e != list_end(&all_list); e = next)
      {
        next = list_next(e);
        struct thread *t = list_entry(e, struct thread, all_list_elem);
        calculate_recent_cpu(t);
        //printf("t->tid : %d\n", t->tid);
      }
    }
    if (curr_thread->status == THREAD_RUNNING && curr_thread != idle_thread) {
      curr_thread->recent_cpu = add_x_n(curr_thread->recent_cpu, 1);
      // printf("add 1 curr_thread->recent_cpu is : %d\n", curr_thread->recent_cpu);
    }
    if ((timer_ticks() % 4) == 0) {
      struct list_elem *e, *next;
      for (e = list_begin(&all_list); e != list_end(&all_list); e = next)
      {
        next = list_next(e);
        struct thread *t = list_entry(e, struct thread, all_list_elem);
        t->priority = priority_recalculate_with_new_nice(t);
        //printf("t->priority : %d, t->recent_cpu : %d\n", t->priority, t->recent_cpu);
      }
    }          
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.
   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.
   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();
  //printf("tid : %d\n", tid);
  
  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;

  /* Add to run queue. */
  thread_unblock (t);
  check_ready_list();

  return tid;
}

// Priority Donation
void priority_donation(struct thread *giver)
{
  if(!list_empty(&giver->waiting_lock_list))
  {
    struct list_elem *e;
    for(e = list_begin(&giver->waiting_lock_list); e != list_end(&giver->waiting_lock_list); e = list_next(e))
    {
      struct lock_waiter *lock_waiter = list_entry(e, struct lock_waiter, elem);
      // struct lock *l = lock_waiter->lock;
      // struct thread *holder_thread = l->holder;
      struct thread *holder_thread = lock_waiter->lock->holder;
      // TODO: holder의 initial priority가 맞나? 왜 initial priority?
      // 생각해보면 lock정보를 넣게 되면 list 로 old를 저장할 필요가 있나? lock A에 대한 가장 높은것만 기억하는게 best?!
      if(holder_thread->initial_priority < giver->priority)
      {
        struct priority_elem *giver_priority_elem = malloc(sizeof(giver_priority_elem));
        giver_priority_elem->priority = giver->priority;
        giver_priority_elem->lock = lock_waiter->lock;
        list_insert_ordered(&holder_thread->old_priority_list, &giver_priority_elem->elem, priority_elem_compare, 0); 
        holder_thread->priority = giver->priority;
        priority_donation(holder_thread);
      }
    }
  }
}

void priority_rollback(struct lock *lock)
{
  enum intr_level old_level;
  old_level = intr_disable ();

  struct thread *curr_thread = thread_current();
  struct semaphore *semaphore = &lock->semaphore;
  struct list *waiters = &semaphore->waiters;
  
  struct list_elem *waiter_elem, *waiter_next;
  for (waiter_elem = list_begin(waiters); waiter_elem != list_end(waiters); waiter_elem = waiter_next)
  {
    waiter_next = list_next(waiter_elem);
    int donor_priority = list_entry(waiter_elem, struct thread, elem)->priority;
    if ((curr_thread->initial_priority < donor_priority) && (list_size(&curr_thread->old_priority_list) > 0)) {
      // list_pop_front(&curr_thread->old_priority_list);
      struct list_elem *e, *next;
      for (e = list_begin(&curr_thread->old_priority_list); e != list_tail(&curr_thread->old_priority_list) ; e = next)
      {
        next = list_next(e);
        struct priority_elem *priority_elem = list_entry(e, struct priority_elem, elem);
        /* if (priority_elem->priority == donor_priority) {
          list_remove(e);
        } */
        if (priority_elem->lock == lock) {
          list_remove(e);
        }
      }
      if (!list_empty(&curr_thread->old_priority_list)) {
        int rollback_priority = list_entry(list_begin(&curr_thread->old_priority_list), struct priority_elem, elem)->priority;
        curr_thread->priority = rollback_priority;
      }
      else {
        curr_thread->priority = curr_thread->initial_priority;
      }
    }
  }
  intr_set_level (old_level); 
}
//
// Compare prioirty of thread
bool priority_compare (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  return list_entry(a, struct thread, elem)->priority > list_entry(b, struct thread, elem)->priority;
}

bool priority_elem_compare (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED)
{
  return list_entry(a, struct priority_elem, elem)->priority > list_entry(b, struct priority_elem, elem)->priority;
}
//

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().
   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)
   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_push_back (&ready_list, &t->elem);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

//
void thread_sleep(int64_t wake_ticks)
{
  struct thread *curr = thread_current ();
  enum intr_level old_level;

  // ASSERT (!intr_context ()); 
  
  old_level = intr_disable();
  ASSERT(curr != idle_thread);
  // curr->status = THREAD_BLOCKED;
  curr->wake_ticks = wake_ticks;
  
  //printf("in thread_sleep prev sleep_list size : %d\n", list_size(&sleep_list));
  list_push_back(&sleep_list, &curr->elem); 
  //printf("in thread_sleep next sleep_list size : %d\n", list_size(&sleep_list));
  
  thread_block();
  // schedule();
  intr_set_level(old_level);
}

void thread_wake(int64_t wake_ticks)
{
  //enum intr_level old_level;

  //ASSERT (!intr_context ());

  //old_level = intr_disable();
  struct list_elem *e, *next;
  //printf("in thread_wake prev sleep list length : %d\n", list_size(&sleep_list));
  for (e = list_begin(&sleep_list); e != list_tail(&sleep_list); e = next)
  {
    next = list_next(e);
    struct thread *t = list_entry(e, struct thread, elem);
    //printf("in thread_wake sleep_thread_wake_ticks : %d, current : %d\n", t->wake_ticks, wake_ticks);
    if ( t->wake_ticks <= wake_ticks )
    {
      // t->status = THREAD_READY;
      list_remove(&t->elem);
      thread_unblock(t);
      //list_push_back(&ready_list, &t->elem);
    }
  }
  //printf("in thread_wake next sleep list length : %d\n", list_size(&sleep_list));
  //schedule();
  //intr_set_level(old_level);
}
//

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Just set our status to dying and schedule another process.
     We will be destroyed during the call to schedule_tail(). */
  intr_disable ();
  // if (thread_mlfqs) {
  list_remove (&thread_current()->all_list_elem);
  // }
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *curr = thread_current ();
  enum intr_level old_level;
  
  ASSERT (!intr_context ());

  old_level = intr_disable ();
  if (curr != idle_thread) 
    list_push_back (&ready_list, &curr->elem);
  curr->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/* when create thread or set priority, check ready_list priority and curr priority */
void
check_ready_list(void)
{
  struct thread *curr = thread_current();
  struct list_elem *e, *next;
   
  if(!list_empty(&ready_list) && curr != idle_thread)
  {
    for(e = list_begin(&ready_list) ; e != list_tail(&ready_list) ; e = next)
    {
      next = list_next(e);
      struct thread *t = list_entry(e, struct thread, elem);
      if(t->priority > curr->priority)
      {
        thread_yield();
        break;
      }
    }
  }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  //
  struct thread *curr = thread_current();
  if (list_empty(&curr->old_priority_list))
  {
    curr->priority = new_priority;
  }
  curr->initial_priority = new_priority;
  //
  check_ready_list();  
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->priority;
}


// priority = PRI_MAX - (recent_cpu / 4) - (nice * 2)
int
priority_recalculate_with_new_nice(struct thread *thread)
{
  if (thread != idle_thread) {
    int cal_priority =
      convert_x_to_int_near(
        sub_x_y(
          sub_x_y(convert_n_to_fixed(PRI_MAX), div_x_n(thread->recent_cpu, 4)),
          mul_n_m(thread->nice, 2)
        )
      );
    if (cal_priority > PRI_MAX) {
      return PRI_MAX;
    } else if (cal_priority < PRI_MIN) {
      return PRI_MIN;
    } else {
      return cal_priority;
    }
  }
}

//recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice
void
calculate_recent_cpu(struct thread *thread)
{
  if(thread != idle_thread) {
    int coeff_recent_cpu_1 = mul_x_n(load_avg, 2);
    int coeff_recent_cpu_2 = add_x_n(coeff_recent_cpu_1, 1);
    // int coeff_recent_cpu_final = div_x_y(coeff_recent_cpu_1, coeff_recent_cpu_2);
    int recent_cpu = thread->recent_cpu;
    thread->recent_cpu = 
      // convert_x_to_int_near(
        add_x_n(
          mul_x_y(
            div_x_y(coeff_recent_cpu_1, coeff_recent_cpu_2),
            recent_cpu),
          thread->nice);
      // );
  }
}

//load_avg = (59/60)*load_avg + (1/60)*ready_threads
void
calculate_load_avg()
{
  struct thread *curr_thread = thread_current();
  int ready_threads;
  if(curr_thread != idle_thread)
  {
    ready_threads = (list_empty(&ready_list) ? 1 : 1+list_size(&ready_list));
    // printf("ready threads %d \n", ready_threads);
  } else {
    ready_threads = (list_empty(&ready_list) ? 0 : 0+list_size(&ready_list));
  }
  // printf("ready threads %d \n", ready_threads);
  int mul_first = mul_x_y(div_n_m(59,60), load_avg);
  int mul_second = mul_x_n(div_n_m(1,60), ready_threads);
  load_avg = 
    // convert_x_to_int_near(
      add_x_y(
        mul_first,
        mul_second
      );
    // );
  // printf("div_n_m(1,60) %d \n", div_n_m(1,60));
  // printf("after calculate load avg %d \n", load_avg);
}
//

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) 
{
  enum intr_level old_level;
  old_level = intr_disable ();

  struct thread *curr_thread = thread_current();
  if (nice > 20) {
    nice = 20;
  }
  if (nice < -20) {
    nice = -20;
  }
  curr_thread->nice = nice;
  int cal_priority = priority_recalculate_with_new_nice(curr_thread);
  thread_set_priority(cal_priority);

  intr_set_level (old_level); 
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  struct thread *curr_thread = thread_current();
  return curr_thread->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return convert_x_to_int_near(mul_x_n(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  /* Not yet implemented. */
  struct thread *curr_thread = thread_current();
  // printf("current thread recent cput %d \n", curr_thread->recent_cpu);
  return convert_x_to_int_near(mul_x_n(curr_thread->recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.
   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.
         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.
         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);
                    
  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Since `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->magic = THREAD_MAGIC;

  //
  list_init(&t->waiting_lock_list);
  list_init(&t->old_priority_list);
  t->initial_priority = priority;

  list_push_back(&all_list, &t->all_list_elem);  

  if (thread_mlfqs) {
    if (t == initial_thread) {
      t->nice = 0;
      t->recent_cpu = convert_n_to_fixed(0);
    } else {
      t->nice = thread_get_nice();
      // t->recent_cpu = thread_get_recent_cpu();
      t->recent_cpu = thread_current()->recent_cpu;
    }
    // t->priority = priority_recalculate_with_new_nice(t);
  }
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
  {
    //
    enum intr_level old_level;
    old_level = intr_disable ();
    int high_priority = 0;
    struct thread *hp_thread = list_entry(list_begin(&ready_list), struct thread, elem);
    struct list_elem *e, *next;
    for (e = list_begin(&ready_list); e != list_tail(&ready_list) ; e = next)
    {
      next = list_next(e);
      struct thread *t = list_entry(e, struct thread, elem);
      if(hp_thread->priority < t->priority)
      {
        hp_thread = t;
      }
    }
    high_priority = hp_thread->priority;
    // priority_donation(hp_thread);
    for (e = list_begin(&ready_list); e != list_tail(&ready_list) ; e = next)
    {
      next = list_next(e);
      struct thread *t = list_entry(e, struct thread, elem);
      // this highest thread doesn't wating any lock
      if (list_empty(&t->waiting_lock_list) && t->priority == high_priority)
      {
        list_remove(&t->elem);
        intr_set_level (old_level);
        return t;
      }
    }
    
    // list_remove(&hp_thread->elem);
    // return hp_thread;
    
    // return list_entry (list_pop_front (&ready_list), struct thread, elem);
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.
   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).
   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.
   After this function and its caller returns, the thread switch
   is complete. */
void
schedule_tail (struct thread *prev) 
{
  struct thread *curr = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  curr->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != curr);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.
   
   It's not safe to call printf() until schedule_tail() has
   completed. */
static void
schedule (void) 
{
  struct thread *curr = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (curr->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (curr != next)
    prev = switch_threads (curr, next);
  schedule_tail (prev); 
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);