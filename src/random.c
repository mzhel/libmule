#include <stdint.h>
#include <stdbool.h>

static uint32_t lcgk1_seed = 0;

#define W (1UL << 32)
#define M W
#define C 362437
#define A 69069

static unsigned long x, y, z, w, v;

static
void
init_lcgk1(
           uint32_t seed
          )
{
  
  do {

    lcgk1_seed = seed;

  } while (false);

}

static
uint32_t
lcgk1()
{
  uint32_t result = false;

  do {

    result = lcgk1_seed = (A * lcgk1_seed * C) % M;

  } while (false);

  return result;
}

static
void
init_xorshift_k5(
                 uint32_t seed
                )
{
  
  do {

    init_lcgk1(seed);

    x = lcgk1();

    y = lcgk1();

    z = lcgk1();

    v = lcgk1();

    w = lcgk1();

  } while (false);

}

uint32_t
xorshift_k5()
{
  uint32_t result = 0;
  uint32_t t;

  do {

    t = (x ^ (x >> 7));

    x = y;

    y = z;

    z = w;
    
    w = v;

    v = (v ^ (v << 6)) ^ (t ^ (t << 13));

    result = (y + y + 1) * v;

  } while (false);

  return result;
}

void
random_init(uint32_t seed)
{

  init_xorshift_k5(seed);

}

uint32_t
random_uint32()
{
  uint32_t val = 0;

  val = xorshift_k5();

  return val;
}

uint16_t
random_uint16()
{
  return (uint16_t)random_uint32();
}

uint8_t
random_uint8()
{
  return (uint8_t)random_uint32();
}
