#ifndef _TICKS_H_
#define _TICKS_H_

#define SEC2MS(sec) ((sec) * 1000)
#define MIN2MS(min) SEC2MS((min) * 60)
#define HR2MS(hr)   MIN2MS((hr) * 60)
#define SEC(sec)    sec
#define MIN2S(min)  ((min) * 60)
#define HR2S(hr)    MIN2S((hr) * 60)
#define DAY2S(day)  HR2S((day) * 24)

uint32_t
ticks_now_ms();

#endif // _TICKS_H_
