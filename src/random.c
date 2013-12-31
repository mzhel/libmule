#include <stdint.h>
#include <polarssl/havege.h>

static havege_state hs = {0};

void
random_init()
{
  havege_init(&hs);
}

uint32_t
random_uint32()
{
  uint32_t val = 0;

  havege_random(&hs, (uint8_t*)&val, sizeof(val));

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
