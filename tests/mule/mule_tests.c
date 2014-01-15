#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <netdb.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <random.h>
#include <ticks.h>
#include <libmule.h>
#include <mem.h>
#include <log.h>
#include <cmockery.h>

void test_success(void** state)
{
  LOG_DEBUG("Successfull test.");
}

void test_mule(void** state)
{
  MULE_SESSION* ms;

  assert_true(mule_session_init(1, &ms));

  assert_true(mule_session_uninit(ms));

}

int main(int argc, char* argv[])
{

  LOG_LEVEL_DEBUG;

  LOG_OUTPUT_CONSOLE;

  LOG_PREFIX("[mule] ");

  random_init();

  const UnitTest tests[] = {
    unit_test(test_success),
    unit_test(test_mule)
  };

  return run_tests(tests);
}
