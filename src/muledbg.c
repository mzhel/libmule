#include <stdint.h>
#include <stdbool.h>
#include <memory.h>
#include <uint128.h>
#include <list.h>
#include <queue.h>
#include <mule.h>
#include <mulesrc.h>
#include <mem.h>
#include <log.h>

char*
muledbg_source_state_by_name(
                             uint32_t state 
                            )
{
  char* result = "Unknown";

  do {

    switch(state){

      case MULE_SOURCE_STATE_NEW:

        result = "MULE_SOURCE_STATE_NEW";

      break;

      case MULE_SOURCE_STATE_CONNECT_QUEUED:

        result = "MULE_SOURCE_STATE_CONNECT_QUEUED";

      break;

      case MULE_SOURCE_STATE_CONNECTED:

        result = "MULE_SOURCE_STATE_CONNECTED";

      break;

      case MULE_SOURCE_STATE_CONNECT_FAILED:

        result = "MULE_SOURCE_STATE_CONNECT_FAILED";

      break;

      case MULE_SOURCE_STATE_HELLO_SENT:

        result = "MULE_SOURCE_STATE_HELLO_SENT";

      break;

      case MULE_SOURCE_STATE_HELLO_RECEIVED:

        result = "MULE_SOURCE_STATE_HELLO_RECEIVED";

      break;

      case MULE_SOURCE_STATE_HANDSHAKE_COMPLETED:

        result = "MULE_SOURCE_STATE_HANDSHAKE_COMPLETED";

      break;

      case MULE_SOURCE_STATE_FILE_INFO_REQUEST_SENT:

        result = "MULE_SOURCE_STATE_FILE_INFO_REQUEST_SENT";

      break;

      case MULE_SOURCE_STATE_FILE_INFO_ANSWER_RECEIVED:

        result = "MULE_SOURCE_STATE_FILE_INFO_ANSWER_RECEIVED";

      break;

      case MULE_SOURCE_STATE_DOWNLOADING:

        result = "MULE_SOURCE_STATE_DOWNLOADING";

      break;

      case MULE_SOURCE_STATE_TIMEOUT_BEFORE_DONE:

        result = "MULE_SOURCE_STATE_TIMEOUT_BEFORE_DONE";

      break;

      case MULE_SOURCE_STATE_ACTION_DONE:

        result = "MULE_SOURCE_STATE_ACTION_DONE";

      break;

      case MULE_SOURCE_STATE_DISCONNECT_QUEUED:

        result = "MULE_SOURCE_STATE_DISCONNECT_QUEUED";

      break;

      case MULE_SOURCE_STATE_DISCONNECTED:

        result = "MULE_SOURCE_STATE_DISCONNECTED";

      break;

    }

  } while (false);

  return result;
}
