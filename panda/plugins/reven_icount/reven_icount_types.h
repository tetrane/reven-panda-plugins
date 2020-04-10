#ifndef __REVEN_ICOUNT_TYPES_H__
#define __REVEN_ICOUNT_TYPES_H__

typedef enum RevenExecStatus {
	REVEN_EXEC_STATUS_NOT_STARTED, // Counting hasn't started yet. Do not call reven_icount
	REVEN_EXEC_STATUS_TRANSLATING, // Currently translating instructions. Panda may call callbacks for memory reads or
	                               // dma accesses, but not memory writes.
	REVEN_EXEC_STATUS_EXEC_INSTR,
	REVEN_EXEC_STATUS_EXEC_INT
} RevenExecStatus;

#endif
