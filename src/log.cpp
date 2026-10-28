#include "log.h"

#include <cstdarg>
#include <cstdio>

namespace ct_bypass::log {
namespace {

constexpr char kSeparator[] =
    "------------------------------------------------------------";
constexpr char kStepIndent[] = "   ";
constexpr char kSubstepIndent[] = "      ";

int current_step = 0;
int current_substep = 0;

// Prints the rest of a line after its header has been written
void finish_line(FILE* stream, const char* format, va_list args) {
  vfprintf(stream, format, args);
  fputc('\n', stream);
}

// Writes a detail line one level below the innermost step or substep
void print_detail(FILE* stream, const char* label, const char* format,
                  va_list args) {
  if (stream != stdout) fflush(stdout);
  fprintf(stream, "%s%s", current_substep > 0 ? kSubstepIndent : kStepIndent,
          label);
  finish_line(stream, format, args);
}

}  // namespace

void step(const char* format, ...) {
  if (current_step > 0) puts(kSeparator);
  ++current_step;
  current_substep = 0;
  printf("Step %d: ", current_step);
  va_list args;
  va_start(args, format);
  finish_line(stdout, format, args);
  va_end(args);
}

void substep(const char* format, ...) {
  ++current_substep;
  printf("%sSubstep %d.%d: ", kStepIndent, current_step, current_substep);
  va_list args;
  va_start(args, format);
  finish_line(stdout, format, args);
  va_end(args);
}

void info(const char* format, ...) {
  va_list args;
  va_start(args, format);
  print_detail(stdout, "", format, args);
  va_end(args);
}

void warn(const char* format, ...) {
  va_list args;
  va_start(args, format);
  print_detail(stderr, "Warning: ", format, args);
  va_end(args);
}

void error(const char* format, ...) {
  va_list args;
  va_start(args, format);
  print_detail(stderr, "Error: ", format, args);
  va_end(args);
}

void result(bool success) {
  puts(kSeparator);
  puts(success ? "SUCCESS" : "FAILED");
  fflush(stdout);
}

}  // namespace ct_bypass::log
