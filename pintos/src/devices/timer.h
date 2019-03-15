
#ifndef DEVICES_TIMER_H
#define DEVICES_TIMER_H

#include <round.h>
#include <stdint.h>
#include <list.h> //


/* Number of timer interrupts per second. */
#define TIMER_FREQ 100

void timer_init (void);
void timer_calibrate (void);

int64_t timer_ticks (void);
int64_t timer_elapsed (int64_t);

//
struct ticks_elem
 {
   int64_t ticks_to_wake; //the tick that need to wake up at some point
   struct list_elem elem;
 };
//

void timer_sleep (int64_t ticks);
void timer_msleep (int64_t milliseconds);
void timer_usleep (int64_t microseconds);
void timer_nsleep (int64_t nanoseconds);

void timer_print_stats (void);
bool ticks_compare (const struct list_elem *a, const struct list_elem *b, void *aux); //

#endif /* devices/timer.h */