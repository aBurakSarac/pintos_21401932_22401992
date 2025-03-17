#ifndef THREADS_FIXED_POINT_H
#define THREADS_FIXED_POINT_H

#include <stdint.h>

/* fixed-point numbers are in signed p.q format where p + q = 31, 
    and f is 1 « q: */
typedef int64_t fixed;
#define Q 14
#define F (1 << Q)

/* Convert n to fixed point: */
#define FIXED(n) ((n) * F)

/* Convert x to integer (rounding toward zero): */
#define INT(x) ((x) / F)

/* Convert x to integer (rounding to nearest): */
#define ROUND(x) (((x) >= 0) ? INT((x) + F/2) : INT((x) - F/2))

/* Add x and y: */
#define ADD(x, y) ((x) + (y))

/* Subtract y from x: */
#define SUB(x, y) ((x) - (y))

/* Add x and n: */
#define ADD_INT(x, n) ((x) + FIXED(n))

/* Subtract n from x: */
#define SUB_INT(x, n) ((x) - FIXED(n))

/* Multiply x by y: */
#define MUL(x, y) (INT((x) * (y)))

/* Multiply x by n: */
#define MUL_INT(x, n) ((x) * (n))

/* Divide x by y: */
#define DIV(x, y) (FIXED((x)) / (y))

/* Divide x by n: */
#define DIV_INT(x, n) ((x) / (n))

#endif /* THREADS_FIXED_POINT_H */