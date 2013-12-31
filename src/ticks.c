#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <memory.h>
#include <log.h>

uint32_t
ticks_now_ms()
{
  struct timespec ts;
  uint32_t result = 0;

  do {

    if (0 != clock_gettime(CLOCK_MONOTONIC, &ts)) {
      
      LOG_ERROR("Failed to get clock time.");

      break;

    }

    result = (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);

  } while (false);

  return result;

}

