#ifndef __REVEN_ICOUNT_INT_FNS_H__
#define __REVEN_ICOUNT_INT_FNS_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Retrieve current instruction count, that is guaranteed to match reven's trace.
// Note: will abort the program if counting hasn't started yet (reven_exec_status returns REVEN_EXEC_STATUS_NOT_STARTED)
// that is if you call it before insn_exec_callback has been called once.
// Note: The current policy mandates that plugins discard elements attached to the reven_icount() values
// that is current in the uninit_plugin function of these plugins. This policy prevents plugins from storing
// partial information about a possibly unfinished last instruction.
uint64_t reven_icount(void);

// Retrieve status of execution as a RevenExecStatus.
// This can be called at any time, but it will not make sense during uninit_plugin.
int reven_exec_status(void);

// Retrieve whether the plugin is holding reven_icount from growing due to an ongoing REP instruction being executed.
// This can be called at any time, but it will not make sense during uninit_plugin.
bool reven_exec_rep_ongoing(void);

#ifdef __cplusplus
}
#endif

#endif // __REVEN_ICOUNT_INT_FNS_H__
