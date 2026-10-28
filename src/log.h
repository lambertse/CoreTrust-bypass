#ifndef CT_BYPASS_LOG_H
#define CT_BYPASS_LOG_H

// Step-structured progress output shared by the library and the CLI:
//
//   Step 1: Ad-hoc sign the binary
//      Substep 1.1: Sign with Security.framework
//         <info / warning / error lines>
//   ------------------------------------------------------------
//   Step 2: ...
//   ------------------------------------------------------------
//   SUCCESS
//
// Numbering is process-wide, so steps logged by the CLI and by the library
// form one sequence. Warnings and errors go to stderr; stdout is flushed
// first so the two streams stay in order when piped.

namespace ct_bypass::log {

#define CT_BYPASS_PRINTF_FORMAT(fmt_index, args_index) \
  __attribute__((format(printf, fmt_index, args_index)))

// Starts the next step, separated from the previous one
void step(const char* format, ...) CT_BYPASS_PRINTF_FORMAT(1, 2);

// Starts the next substep of the current step
void substep(const char* format, ...) CT_BYPASS_PRINTF_FORMAT(1, 2);

// Detail line under the current step or substep
void info(const char* format, ...) CT_BYPASS_PRINTF_FORMAT(1, 2);

// "Warning: " / "Error: " line under the current step or substep (stderr)
void warn(const char* format, ...) CT_BYPASS_PRINTF_FORMAT(1, 2);
void error(const char* format, ...) CT_BYPASS_PRINTF_FORMAT(1, 2);

// Closes the run with a separator and SUCCESS or FAILED
void result(bool success);

#undef CT_BYPASS_PRINTF_FORMAT

}  // namespace ct_bypass::log

#endif  // CT_BYPASS_LOG_H
